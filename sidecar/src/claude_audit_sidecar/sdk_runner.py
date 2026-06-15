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


class ClaudeSdkRunner:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def query(self, request: QueryRequest) -> str:
        options = ClaudeAgentOptions(
            tools=[],
            allowed_tools=[],
            permission_mode="dontAsk",
            cwd=request.working_directory,
            setting_sources=[],
            env={"CLAUDE_AGENT_SDK_CLIENT_APP": "huawei-code-audit-sidecar/0.1.0"},
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
            setting_sources=[],
            env={"CLAUDE_AGENT_SDK_CLIENT_APP": "huawei-code-audit-sidecar/0.1.0"},
        )
        active: dict[str, str] = {}
        completed = 0
        try:
            async for message in query(prompt=request.prompt, options=options):
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
                    case (
                        UserMessage()
                        | SystemMessage()
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
        result[name] = AgentDefinition(**kwargs)
    return result


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
