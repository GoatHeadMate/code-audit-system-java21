"""Tests for the native /goal driver and its real plain-prompt fallback.

These talk to ClaudeSdkRunner.supervise directly with a monkeypatched `query`,
so they do not import the FastAPI TestClient and are unaffected by the
pre-existing httpx2 collection error in test_api.py.
"""

import asyncio
from pathlib import Path
from types import SimpleNamespace

from claude_agent_sdk import ResultMessage, SystemMessage

from claude_audit_sidecar import sdk_runner
from claude_audit_sidecar.models import (
    AssistantTextEvent,
    ResultEvent,
    SuperviseRequest,
)

_ENVELOPE = '{"selected_hunters":[],"rationale":"r","findings":[]}'
_GOAL_SENTINEL = "/goal isn't available in this environment."


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        anthropic_api_key=None, anthropic_base_url=None, max_turns=20
    )


def _init(slash_commands: list[str]) -> SystemMessage:
    return SystemMessage(subtype="init", data={"slash_commands": slash_commands})


def _result(text: str, session_id: str = "s1") -> ResultMessage:
    return ResultMessage(
        subtype="success",
        duration_ms=0,
        duration_api_ms=0,
        is_error=False,
        num_turns=1,
        session_id=session_id,
        result=text,
    )


def _fake_query(scripts: list[list[object]], calls: list[str]):
    def fake(*, prompt: str, options: object):
        scripted = scripts[len(calls)]
        calls.append(prompt)

        async def gen():
            for message in scripted:
                yield message

        return gen()

    return fake


def _request(prompt: str = "SYSTEM:\nx\n\nUSER:\ny") -> SuperviseRequest:
    return SuperviseRequest(
        prompt=prompt,
        working_directory=Path("."),
        source_root=Path("."),
    )


def _drain(runner: sdk_runner.ClaudeSdkRunner, request: SuperviseRequest):
    async def _collect():
        return [event async for event in runner.supervise(request)]

    return asyncio.run(_collect())


def test_goal_directive_targets_selected_hunters_only():
    # Must be sent as the leading slash command, and must NOT force delegating
    # every candidate (would conflict with the supervisor's intelligent selection).
    assert sdk_runner._GOAL_DIRECTIVE.startswith("/goal ")
    assert "最终选中" in sdk_runner._GOAL_DIRECTIVE
    assert "不要求委派全部候选" in sdk_runner._GOAL_DIRECTIVE


def test_goal_prompt_used_when_exposed(monkeypatch):
    calls: list[str] = []
    script = [_init(["goal", "loop"]), _result(_ENVELOPE)]
    monkeypatch.setattr(sdk_runner, "query", _fake_query([script], calls))

    events = _drain(sdk_runner.ClaudeSdkRunner(_settings()), _request())

    assert len(calls) == 1
    assert calls[0].startswith("/goal ")
    results = [e for e in events if isinstance(e, ResultEvent)]
    assert len(results) == 1
    assert results[0].result == _ENVELOPE


def test_falls_back_to_plain_prompt_when_goal_missing(monkeypatch):
    calls: list[str] = []
    request = _request()
    goal_script = [_init(["compact"]), _result(_GOAL_SENTINEL)]
    plain_script = [_init(["compact"]), _result(_ENVELOPE, session_id="s2")]
    monkeypatch.setattr(
        sdk_runner, "query", _fake_query([goal_script, plain_script], calls)
    )

    events = _drain(sdk_runner.ClaudeSdkRunner(_settings()), request)

    # Real fallback: a second query with the PLAIN prompt (no /goal prefix).
    assert len(calls) == 2
    assert calls[0].startswith("/goal ")
    assert calls[1] == request.prompt
    assert any(
        isinstance(e, AssistantTextEvent) and "not exposed" in e.text
        for e in events
    )
    results = [e for e in events if isinstance(e, ResultEvent)]
    assert len(results) == 1
    # The supervisor result is the real envelope, never the slash-command sentinel.
    assert results[0].result == _ENVELOPE
    assert "available" not in results[0].result


def test_falls_back_when_goal_returns_sentinel(monkeypatch):
    # Backup path: `goal` is exposed in init but the CLI still returns the
    # "/goal isn't available" sentinel as the result.
    calls: list[str] = []
    request = _request()
    goal_script = [_init(["goal"]), _result(_GOAL_SENTINEL)]
    plain_script = [_init(["goal"]), _result(_ENVELOPE, session_id="s2")]
    monkeypatch.setattr(
        sdk_runner, "query", _fake_query([goal_script, plain_script], calls)
    )

    events = _drain(sdk_runner.ClaudeSdkRunner(_settings()), request)

    assert len(calls) == 2
    assert calls[1] == request.prompt
    results = [e for e in events if isinstance(e, ResultEvent)]
    assert len(results) == 1
    assert results[0].result == _ENVELOPE
