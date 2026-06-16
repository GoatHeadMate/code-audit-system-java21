from collections.abc import AsyncIterator

import pytest
from fastapi.testclient import TestClient

from claude_audit_sidecar.app import create_app
from claude_audit_sidecar.models import QueryRequest, SidecarEvent, SuperviseRequest
from claude_audit_sidecar.settings import Settings


class FakeRunner:
    async def query(self, request: QueryRequest) -> str:
        return f"answer:{request.prompt}"

    async def supervise(self, request: SuperviseRequest) -> AsyncIterator[SidecarEvent]:
        yield SidecarEvent(
            type="subagent_started",
            agent="authorization",
            description="Review authorization paths",
        )
        yield SidecarEvent(
            type="result",
            result='{"findings":[]}',
            session_id="session-1",
        )


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(FakeRunner()))


def test_health_reports_agent_sdk_ready(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "runtime": "claude-agent-sdk-python",
    }


def test_query_returns_sdk_result(client: TestClient) -> None:
    response = client.post(
        "/v1/query",
        json={"prompt": "audit", "working_directory": "D:/workspace"},
    )

    assert response.status_code == 200
    assert response.json() == {"result": "answer:audit"}


def test_supervise_streams_typed_ndjson_events(client: TestClient) -> None:
    with client.stream(
        "POST",
        "/v1/supervise",
        json={
            "prompt": "audit",
            "working_directory": "D:/workspace",
            "source_root": "D:/workspace/src",
        },
    ) as response:
        lines = list(response.iter_lines())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert lines == [
        (
            '{"type":"subagent_started","agent":"authorization",'
            '"description":"Review authorization paths"}'
        ),
        (
            '{"type":"result","result":"{\\"findings\\":[]}",'
            '"session_id":"session-1"}'
        ),
    ]


def test_query_rejects_invalid_token() -> None:
    app = create_app(FakeRunner(), Settings(api_token="secret"))
    client = TestClient(app)

    response = client.post(
        "/v1/query",
        headers={"Authorization": "Bearer wrong"},
        json={"prompt": "audit", "working_directory": "D:/workspace"},
    )

    assert response.status_code == 401
