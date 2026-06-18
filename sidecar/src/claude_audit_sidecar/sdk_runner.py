from collections.abc import AsyncIterator
from typing import Literal, assert_never

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
# init message's slash_commands the line degrades to a plain (still valid)
# instruction. /loop is deliberately NOT used: it is a scheduled, repeating
# bundled skill that needs a long-lived ClaudeSDKClient, not a one-shot query().
_GOAL_DIRECTIVE = (
    "/goal 完成本次白盒安全审计, 在满足以下全部完成条件前不要结束: "
    "(1) 已为每个候选 Hunter 委派其对应子代理; "
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

    async def supervise(
        self,
        request: SuperviseRequest,
    ) -> AsyncIterator[SidecarEvent]:
        agents = _build_agents(request.agents) if request.agents else {}
        options = ClaudeAgentOptions(
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
                "append": _SUPERVISOR_SYSTEM_PROMPT,
            },
            agents=agents,
            skills="all",
            # "user" keeps Claude auth/settings; "project" makes the per-job
            # .claude/skills/ generated under cwd discoverable by the CLI.
            setting_sources=["user", "project"],
            env=self._env,
        )
        goal_prompt = f"{_GOAL_DIRECTIVE}\n\n{request.prompt}"
        active: dict[str, str] = {}
        completed = 0
        try:
            async for message in query(prompt=goal_prompt, options=options):
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
                                    yield AssistantTextEvent(text=_preview(text.strip(), 300))
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
                        yield ResultEvent(
                            result=result,
                            session_id=session_id,
                            total_cost_usd=total_cost_usd,
                        )
                    case ResultMessage(is_error=True, errors=errors):
                        yield ErrorEvent(
                            message="; ".join(errors or ["Claude supervisor failed"])
                        )
                    case SystemMessage() as system_message:
                        if getattr(system_message, "subtype", None) == "init":
                            yield AssistantTextEvent(
                                text=_goal_mode_status(
                                    getattr(system_message, "data", None)
                                )
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
        except ClaudeSDKError as error:
            yield ErrorEvent(message=str(error))


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


def _goal_mode_status(data: object) -> str:
    commands = data.get("slash_commands", []) if isinstance(data, dict) else []
    if "goal" in commands:
        return (
            "[goal-mode] /goal active; running until the completion condition "
            f"is met (loop available={'loop' in commands})"
        )
    return (
        "[goal-mode] /goal not exposed; falling back to a plain goal instruction "
        "-- verify the workspace is trusted and hooks are enabled"
    )


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
