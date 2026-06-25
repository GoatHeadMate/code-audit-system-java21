from collections.abc import AsyncIterator
from typing import Literal, assert_never, cast

from claude_agent_sdk import (
    AgentDefinition,
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKError,
    RateLimitEvent,
    ResultMessage,
    ServerToolResultBlock,
    ServerToolUseBlock,
    StreamEvent,
    SystemMessage,
    TaskNotificationMessage,
    TaskStartedMessage,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    query,
)

from claude_audit_sidecar.errors import ClaudeExecutionError
from claude_audit_sidecar.models import (
    AgentDef,
    AssistantTextEvent,
    ErrorEvent,
    QueryRequest,
    ResultEvent,
    SidecarEvent,
    SubagentCompletedEvent,
    SubagentStartedEvent,
    SuperviseRequest,
)
from claude_audit_sidecar.settings import Settings

_SUPERVISOR_SYSTEM_PROMPT = (
    "You are in goal mode. Work autonomously toward the audit objective. "
    "Do not ask clarifying questions. Break down the goal into subtasks, "
    "delegate to subagents, and synthesize results independently."
)
_READ_ONLY_TOOLS = ["Agent", "SendMessage", "Read", "Glob", "Grep"]

# The native /goal slash command (Claude Code >= 2.1.139; the bundled CLI here is
# 2.1.179) turns this one-shot query() into a goal-driven run that continues until
# the stated completion condition is met (session goal + Stop-hook evaluator) —
# the real mechanism behind the prose "goal mode" hint above. It is delivered as
# the FIRST characters of the query prompt, not via a ClaudeAgentOptions field.
# Requires a trusted workspace with hooks enabled; if `goal` is absent from the
# init message's slash_commands we restart with a plain prompt instead. /loop is
# deliberately NOT used: it is a scheduled, repeating bundled skill that needs a
# long-lived ClaudeSDKClient, not a one-shot query().
#
# IMPORTANT: the CLI treats the WHOLE /goal message as the completion condition,
# which it caps at 4000 characters. So the directive below must stay short and the
# full audit task is delivered via the system prompt (see _supervise_options'
# task_context) rather than appended after the directive.
_GOAL_DIRECTIVE = (
    "/goal 完成本次白盒安全审计, 在满足以下全部完成条件前不要结束: "
    "(1) 已按本会话的选择策略与上限为每个最终选中的 Hunter 委派其对应子代理 "
    "(遵循智能选择, 不要求委派全部候选); "
    "(2) 已复核所有子代理返回的发现并剔除重复与明显误报; "
    "(3) 已产出唯一的最终 JSON 对象(字段: selected_hunters, rationale, findings)."
)


class ClaudeSdkRunner:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._env = self._build_env(settings)

    @staticmethod
    def _build_env(settings: Settings) -> dict[str, str]:
        env: dict[str, str] = {
            "CLAUDE_AGENT_SDK_CLIENT_APP": "huawei-code-audit-sidecar/0.1.0",
        }
        if settings.anthropic_api_key:
            env["ANTHROPIC_API_KEY"] = settings.anthropic_api_key
        if settings.anthropic_base_url:
            env["ANTHROPIC_BASE_URL"] = settings.anthropic_base_url
        return env

    async def query(self, request: QueryRequest) -> str:
        options = ClaudeAgentOptions(
            tools=[],
            allowed_tools=[],
            permission_mode="dontAsk",
            cwd=request.working_directory,
            setting_sources=["user"],
            env=self._env,
        )
        try:
            async for message in query(prompt=request.prompt, options=options):
                match message:
                    case ResultMessage(is_error=False, result=str() as result):
                        return result
                    case ResultMessage(is_error=True, errors=errors):
                        detail = "; ".join(errors or ["Claude query failed"])
                        raise ClaudeExecutionError(detail=detail)
                    case (
                        AssistantMessage()
                        | UserMessage()
                        | SystemMessage()
                        | StreamEvent()
                        | RateLimitEvent()
                    ):
                        continue
                    case unreachable:
                        assert_never(unreachable)
        except ClaudeSDKError as error:
            raise ClaudeExecutionError(detail=str(error)) from error
        raise ClaudeExecutionError(detail="Claude query returned no result")

    def _supervise_options(
        self,
        request: SuperviseRequest,
        agents: dict[str, AgentDefinition],
        task_context: str | None = None,
    ) -> ClaudeAgentOptions:
        # In goal mode the full audit task rides in the system prompt (no length
        # limit) because the /goal user message is capped at 4000 chars; the plain
        # fallback leaves the task in the user prompt and appends nothing here.
        append = _SUPERVISOR_SYSTEM_PROMPT
        if task_context:
            append = f"{append}\n\n{task_context}"
        return ClaudeAgentOptions(
            tools=_READ_ONLY_TOOLS,
            allowed_tools=_READ_ONLY_TOOLS,
            disallowed_tools=[
                "Bash",
                "Write",
                "Edit",
                "NotebookEdit",
                "WebFetch",
                "WebSearch",
            ],
            permission_mode="bypassPermissions",
            cwd=request.working_directory,
            add_dirs=[request.source_root],
            max_turns=self._settings.max_turns,
            system_prompt={
                "type": "preset",
                "preset": "claude_code",
                "append": append,
            },
            agents=agents,
            skills="all",
            # "user" keeps Claude auth/settings; "project" makes the per-job
            # .claude/skills/ generated under cwd discoverable by the CLI.
            setting_sources=["user", "project"],
            env=self._env,
        )

    async def supervise(
        self,
        request: SuperviseRequest,
    ) -> AsyncIterator[SidecarEvent]:
        agents = _build_agents(request.agents) if request.agents else {}
        plain_prompt = request.prompt
        # Drive the run with /goal first. The goal attempt sends only the short
        # _GOAL_DIRECTIVE as the user prompt (the 4000-char-capped completion
        # condition) and carries the full task in the system prompt. If this
        # session does not expose the `goal` slash command (seen in the init
        # message) or the CLI returns the "/goal isn't available" sentinel,
        # transparently RESTART with the plain prompt — so the supervisor result
        # is always a real audit envelope, never the slash-command error string.
        attempts = (
            (True, _GOAL_DIRECTIVE, plain_prompt),
            (False, plain_prompt, None),
        )
        for is_goal, prompt, task_context in attempts:
            options = self._supervise_options(request, agents, task_context)
            restart_plain = [False]
            async for event in self._stream_attempt(
                prompt,
                is_goal=is_goal,
                options=options,
                restart_plain=restart_plain,
            ):
                yield event
            if not restart_plain[0]:
                return

    async def _stream_attempt(
        self,
        prompt: str,
        *,
        is_goal: bool,
        options: ClaudeAgentOptions,
        restart_plain: list[bool],
    ) -> AsyncIterator[SidecarEvent]:
        active: dict[str, str] = {}
        completed = 0
        stream = query(prompt=prompt, options=options)
        try:
            async for message in stream:
                match message:
                    case TaskStartedMessage(
                        task_id=task_id,
                        description=description,
                        task_type=task_type,
                    ):
                        agent = task_type or task_id
                        active[task_id] = agent
                        yield SubagentStartedEvent(
                            agent=agent,
                            description=description,
                        )
                    case TaskNotificationMessage(
                        task_id=task_id,
                        status=status,
                        summary=summary,
                    ):
                        completed += 1
                        agent = active.pop(task_id, task_id)
                        yield SubagentCompletedEvent(
                            agent=agent,
                            status=_completion_status(status),
                            completed=completed,
                            total=max(completed, completed + len(active)),
                            result_size=_result_size(summary),
                            preview=_preview(summary),
                        )
                    case AssistantMessage(content=content):
                        for block in content:
                            match block:
                                case TextBlock(text=text) if text.strip():
                                    yield AssistantTextEvent(
                                        text=_preview(text.strip(), 300)
                                    )
                                case (
                                    TextBlock()
                                    | ThinkingBlock()
                                    | ToolUseBlock()
                                    | ToolResultBlock()
                                    | ServerToolUseBlock()
                                    | ServerToolResultBlock()
                                ):
                                    continue
                                case unreachable:
                                    assert_never(unreachable)
                    case ResultMessage(
                        is_error=False,
                        result=str() as result,
                        session_id=session_id,
                        total_cost_usd=total_cost_usd,
                    ):
                        if is_goal and _is_goal_unavailable(result):
                            yield AssistantTextEvent(
                                text=_goal_unavailable_notice()
                            )
                            restart_plain[0] = True
                            return
                        yield ResultEvent(
                            result=result,
                            session_id=session_id,
                            total_cost_usd=total_cost_usd,
                        )
                        return
                    case ResultMessage(is_error=True, errors=errors):
                        yield ErrorEvent(
                            message="; ".join(
                                errors or ["Claude supervisor failed"]
                            )
                        )
                        # A ResultMessage is terminal. Stop here so the wrapped
                        # exception the SDK then raises for the same failure
                        # (e.g. max_turns) does not become a second ErrorEvent.
                        return
                    case SystemMessage() as system_message:
                        if getattr(system_message, "subtype", None) == "init":
                            commands = _slash_commands(
                                getattr(system_message, "data", None)
                            )
                            if is_goal and "goal" not in commands:
                                yield AssistantTextEvent(
                                    text=_goal_unavailable_notice()
                                )
                                restart_plain[0] = True
                                return
                            if is_goal:
                                yield AssistantTextEvent(
                                    text=_goal_active_notice(commands)
                                )
                        continue
                    case (
                        UserMessage()
                        | StreamEvent()
                        | RateLimitEvent()
                    ):
                        continue
                    case unreachable:
                        assert_never(unreachable)
        except Exception as error:  # noqa: BLE001
            # Stream boundary: every failure — including the plain Exception the
            # SDK raises when a run hits max_turns — must surface as a typed
            # ErrorEvent so the NDJSON stream ends cleanly instead of breaking.
            yield ErrorEvent(message=str(error))
        finally:
            aclose = getattr(stream, "aclose", None)
            if aclose is not None:
                await aclose()


def _build_agents(
    defs: dict[str, AgentDef],
) -> dict[str, AgentDefinition]:
    result: dict[str, AgentDefinition] = {}
    for name, defn in defs.items():
        kwargs: dict[str, object] = {
            "description": defn.description,
            "prompt": defn.prompt,
            "tools": defn.tools,
        }
        if defn.model is not None:
            kwargs["model"] = defn.model
        if defn.skills:
            kwargs["skills"] = defn.skills
        result[name] = AgentDefinition(**kwargs)
    return result


def _slash_commands(data: object) -> list[str]:
    if not isinstance(data, dict):
        return []
    mapping = cast("dict[str, object]", data)
    commands = mapping.get("slash_commands")
    if not isinstance(commands, list):
        return []
    return [str(command) for command in cast("list[object]", commands)]


def _goal_active_notice(commands: list[str]) -> str:
    return (
        "[goal-mode] /goal active; running until the completion condition is met "
        f"(loop available={'loop' in commands})"
    )


def _goal_unavailable_notice() -> str:
    return (
        "[goal-mode] /goal not exposed; restarting with a plain prompt -- to "
        "enable it, ensure the workspace is trusted and hooks are not disabled"
    )


def _is_goal_unavailable(result: str) -> bool:
    stripped = result.lstrip()
    return stripped.startswith("/goal") and "available" in result.lower()


def _completion_status(
    status: str,
) -> Literal["done", "failed", "stopped"]:
    match status:
        case "completed":
            return "done"
        case "failed":
            return "failed"
        case "stopped":
            return "stopped"
        case _:
            return "failed"


def _result_size(value: str) -> str:
    length = len(value.encode())
    if length < 1_024:
        return f"{length} B"
    return f"{length / 1_024:.1f} KB"


def _preview(value: str, limit: int = 200) -> str:
    flattened = value.replace("\n", " | ")
    return flattened if len(flattened) <= limit else f"{flattened[:limit]}…"
