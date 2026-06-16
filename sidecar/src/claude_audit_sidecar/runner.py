from collections.abc import AsyncIterator
from typing import Protocol

from claude_audit_sidecar.models import QueryRequest, SidecarEvent, SuperviseRequest


class ClaudeRunner(Protocol):
    async def query(self, request: QueryRequest) -> str: ...

    def supervise(self, request: SuperviseRequest) -> AsyncIterator[SidecarEvent]: ...

