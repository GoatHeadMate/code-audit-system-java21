from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class QueryRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    prompt: str = Field(min_length=1)
    working_directory: Path


class QueryResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    result: str


class AgentDef(BaseModel):
    model_config = ConfigDict(frozen=True)

    description: str
    prompt: str
    tools: list[str] = Field(default_factory=lambda: ["Read", "Glob", "Grep"])
    model: str | None = None


class SuperviseRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    prompt: str = Field(min_length=1)
    working_directory: Path
    source_root: Path
    agents: dict[str, AgentDef] = Field(default_factory=dict)


class SubagentStartedEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal["subagent_started"] = "subagent_started"
    agent: str
    description: str


class SubagentCompletedEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal["subagent_completed"] = "subagent_completed"
    agent: str
    status: Literal["done", "failed", "stopped"]
    completed: int = Field(ge=0)
    total: int = Field(ge=0)
    result_size: str
    preview: str


class AssistantTextEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal["assistant_text"] = "assistant_text"
    text: str


class ResultEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal["result"] = "result"
    result: str
    session_id: str
    total_cost_usd: float | None = None


class ErrorEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal["error"] = "error"
    message: str


SidecarEvent = Annotated[
    SubagentStartedEvent
    | SubagentCompletedEvent
    | AssistantTextEvent
    | ResultEvent
    | ErrorEvent,
    Field(discriminator="type"),
]


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: Literal["ok"] = "ok"
    runtime: Literal["claude-agent-sdk-python"] = "claude-agent-sdk-python"
