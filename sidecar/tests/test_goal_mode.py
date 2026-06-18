"""Tests for the native /goal driver and its real plain-prompt fallback.

These talk to ClaudeSdkRunner.supervise directly with a monkeypatched `query`,
so they do not import the FastAPI TestClient and are unaffected by the
pre-existing httpx2 collection error in test_api.py.
"""

import asyncio
from collections.abc import AsyncIterator, Callable, Sequence
from pathlib import Path

import pytest
from claude_agent_sdk import ResultMessage, SystemMessage

from claude_audit_sidecar import sdk_runner
from claude_audit_sidecar.models import (
    AssistantTextEvent,
    ErrorEvent,
    ResultEvent,
    SidecarEvent,
    SuperviseRequest,
)
from claude_audit_sidecar.sdk_runner import ClaudeSdkRunner
from claude_audit_sidecar.settings import Settings

_ENVELOPE = '{"selected_hunters":[],"rationale":"r","findings":[]}'
_GOAL_SENTINEL = "/goal isn't available in this environment."
_MAX_TURNS_MESSAGE = (
    "Claude Code returned an error result: Reached maximum number of turns (2)"
)


def _settings() -> Settings:
    return Settings(max_turns=20)


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


def _error_result(errors: list[str], session_id: str = "s1") -> ResultMessage:
    return ResultMessage(
        subtype="error_max_turns",
        duration_ms=0,
        duration_api_ms=0,
        is_error=True,
        num_turns=1,
        session_id=session_id,
        errors=errors,
    )


def _fake_query(
    scripts: Sequence[Sequence[object]], calls: list[str]
) -> Callable[..., AsyncIterator[object]]:
    def fake(*, prompt: str, **_kwargs: object) -> AsyncIterator[object]:
        scripted = scripts[len(calls)]
        calls.append(prompt)

        async def gen() -> AsyncIterator[object]:
            for message in scripted:
                yield message

        return gen()

    return fake


def _request(prompt: str = "SYSTEM:\nx\n\nUSER:\ny") -> SuperviseRequest:
    return SuperviseRequest(
        prompt=prompt,
        working_directory=Path(),
        source_root=Path(),
    )


def _drain(
    runner: ClaudeSdkRunner, request: SuperviseRequest
) -> list[SidecarEvent]:
    async def _collect() -> list[SidecarEvent]:
        return [event async for event in runner.supervise(request)]

    return asyncio.run(_collect())


def test_goal_prompt_used_when_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    script = [_init(["goal", "loop"]), _result(_ENVELOPE)]
    monkeypatch.setattr(sdk_runner, "query", _fake_query([script], calls))

    events = _drain(ClaudeSdkRunner(_settings()), _request())

    assert len(calls) == 1
    # Slash command must lead the prompt, and the goal condition must not force
    # delegating every candidate (it follows the supervisor's selection).
    assert calls[0].startswith("/goal ")
    assert "最终选中" in calls[0]
    assert "不要求委派全部候选" in calls[0]
    results = [e for e in events if isinstance(e, ResultEvent)]
    assert len(results) == 1
    assert results[0].result == _ENVELOPE


def test_falls_back_to_plain_prompt_when_goal_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    request = _request()
    goal_script = [_init(["compact"]), _result(_GOAL_SENTINEL)]
    plain_script = [_init(["compact"]), _result(_ENVELOPE, session_id="s2")]
    monkeypatch.setattr(
        sdk_runner, "query", _fake_query([goal_script, plain_script], calls)
    )

    events = _drain(ClaudeSdkRunner(_settings()), request)

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


def test_falls_back_when_goal_returns_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Backup path: `goal` is exposed in init but the CLI still returns the
    # "/goal isn't available" sentinel as the result.
    calls: list[str] = []
    request = _request()
    goal_script = [_init(["goal"]), _result(_GOAL_SENTINEL)]
    plain_script = [_init(["goal"]), _result(_ENVELOPE, session_id="s2")]
    monkeypatch.setattr(
        sdk_runner, "query", _fake_query([goal_script, plain_script], calls)
    )

    events = _drain(ClaudeSdkRunner(_settings()), request)

    assert len(calls) == 2
    assert calls[1] == request.prompt
    results = [e for e in events if isinstance(e, ResultEvent)]
    assert len(results) == 1
    assert results[0].result == _ENVELOPE


def test_max_turns_is_converted_to_error_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The SDK raises a plain Exception (NOT ClaudeSDKError) when a run hits
    # max_turns; the stream boundary must surface it as a typed ErrorEvent
    # instead of letting it break the NDJSON stream. No plain-prompt retry:
    # max_turns is a real failure, not a /goal-availability problem.
    calls: list[str] = []

    def raising_query(*, prompt: str, **_kwargs: object) -> AsyncIterator[object]:
        calls.append(prompt)

        async def gen() -> AsyncIterator[object]:
            yield _init(["goal"])
            raise Exception(_MAX_TURNS_MESSAGE)  # noqa: TRY002

        return gen()

    monkeypatch.setattr(sdk_runner, "query", raising_query)

    events = _drain(ClaudeSdkRunner(_settings()), _request())

    assert len(calls) == 1
    errors = [e for e in events if isinstance(e, ErrorEvent)]
    assert len(errors) == 1
    assert "maximum number of turns" in errors[0].message


def test_max_turns_result_then_raise_yields_single_error_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Real protocol: the SDK first yields ResultMessage(is_error=True) and THEN
    # the stream raises the wrapped Exception for the same failure. Exactly one
    # ErrorEvent must result — the terminal ResultMessage stops the attempt so
    # the trailing exception is not converted into a second event.
    calls: list[str] = []

    def raising_query(*, prompt: str, **_kwargs: object) -> AsyncIterator[object]:
        calls.append(prompt)

        async def gen() -> AsyncIterator[object]:
            yield _init(["goal"])
            yield _error_result(["Reached maximum number of turns (1)"])
            raise Exception(_MAX_TURNS_MESSAGE)  # noqa: TRY002

        return gen()

    monkeypatch.setattr(sdk_runner, "query", raising_query)

    events = _drain(ClaudeSdkRunner(_settings()), _request())

    assert len(calls) == 1
    errors = [e for e in events if isinstance(e, ErrorEvent)]
    assert len(errors) == 1
    assert "maximum number of turns" in errors[0].message
