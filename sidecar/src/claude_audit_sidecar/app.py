from collections.abc import AsyncIterator

import orjson
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import ORJSONResponse, StreamingResponse

from claude_audit_sidecar.errors import ClaudeExecutionError
from claude_audit_sidecar.models import (
    HealthResponse,
    QueryRequest,
    QueryResponse,
    SidecarEvent,
    SuperviseRequest,
)
from claude_audit_sidecar.runner import ClaudeRunner
from claude_audit_sidecar.sdk_runner import ClaudeSdkRunner
from claude_audit_sidecar.settings import Settings


def create_app(
    runner: ClaudeRunner | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    effective_settings = settings or Settings()
    effective_runner = runner or ClaudeSdkRunner(effective_settings)
    app = FastAPI(
        title="Claude Audit Sidecar",
        version="0.1.0",
        default_response_class=ORJSONResponse,
    )

    def authorize(authorization: str | None = Header(default=None)) -> None:
        token = effective_settings.api_token
        if token and authorization != f"Bearer {token}":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid sidecar token",
            )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse()

    @app.post(
        "/v1/query",
        response_model=QueryResponse,
        dependencies=[Depends(authorize)],
    )
    async def one_shot(request: QueryRequest) -> QueryResponse:
        try:
            return QueryResponse(result=await effective_runner.query(request))
        except ClaudeExecutionError as error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(error),
            ) from error

    @app.post(
        "/v1/supervise",
        dependencies=[Depends(authorize)],
    )
    async def supervise(request: SuperviseRequest) -> StreamingResponse:
        async def stream() -> AsyncIterator[bytes]:
            async for event in effective_runner.supervise(request):
                yield _encode_event(event)

        return StreamingResponse(
            stream(),
            media_type="application/x-ndjson",
        )

    return app


def _encode_event(event: SidecarEvent) -> bytes:
    return orjson.dumps(event.model_dump(exclude_none=True)) + b"\n"


app = create_app()

