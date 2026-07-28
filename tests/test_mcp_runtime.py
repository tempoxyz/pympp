"""Focused tests for explicit MCP use of ``PaymentRuntime``."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential, PaymentOutcomeUnknownError
from mpp.extensions.mcp import META_CREDENTIAL, McpClient
from mpp.runtime import PaymentRuntime, payment_flow_active


class McpError(Exception):
    def __init__(self, challenges: list[dict[str, Any]]) -> None:
        super().__init__("Payment required")
        self.code = -32042
        self.data = {"challenges": challenges}


class Result:
    meta = None


class Session:
    def __init__(self, *items: Any) -> None:
        self.items = list(items)
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    async def call_tool(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class Method:
    name = "tempo"
    intents = {"charge": object()}

    def __init__(self) -> None:
        self.calls = 0
        self.loops: list[asyncio.AbstractEventLoop] = []

    async def create_credential(self, challenge: Challenge) -> Credential:
        self.calls += 1
        self.loops.append(asyncio.get_running_loop())
        return Credential(
            challenge=challenge.to_echo(),
            payload={"type": "transaction", "signature": "0xabc"},
        )


def challenge(
    challenge_id: str = "challenge-1",
    *,
    realm: str = "api.example.com",
    expires: Any = None,
) -> dict[str, Any]:
    value = {
        "id": challenge_id,
        "realm": realm,
        "method": "tempo",
        "intent": "charge",
        "request": {"amount": "1"},
    }
    if expires is not None:
        value["expires"] = expires
    return value


def payment_error(*challenges: dict[str, Any]) -> McpError:
    return McpError(list(challenges) or [challenge()])


@pytest.mark.asyncio
async def test_runtime_pays_and_preserves_result_metadata_and_events() -> None:
    method = Method()
    result = Result()
    session = Session(payment_error(), result)
    events: list[Any] = []
    runtime = PaymentRuntime([method], allowed_origins=["https://api.example.com"])
    runtime.events.on("*", events.append)
    progress = object()

    try:
        actual = await runtime.call_mcp_tool(
            session.call_tool,
            "premium",
            {"query": "test"},
            None,
            progress,
            meta={"trace": "abc"},
        )
    finally:
        await runtime.aclose()

    assert actual is result
    assert session.calls[1][0] == ("premium", {"query": "test"}, None, progress)
    assert session.calls[1][1]["meta"]["trace"] == "abc"
    assert META_CREDENTIAL in session.calls[1][1]["meta"]
    assert [event.name for event in events] == [
        "challenge.received",
        "credential.created",
        "payment.response",
    ]
    assert all(event.payload["protocol"] == "mcp" for event in events)


@pytest.mark.asyncio
async def test_payment_flow_scope_excludes_mcp_session_calls() -> None:
    states: list[tuple[str, bool]] = []

    class ScopedMethod(Method):
        async def create_credential(self, challenge: Challenge) -> Credential:
            states.append(("method", payment_flow_active()))
            return await super().create_credential(challenge)

    calls = 0

    async def call_tool(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal calls
        states.append(("session", payment_flow_active()))
        calls += 1
        if calls == 1:
            raise payment_error()
        return Result()

    runtime = PaymentRuntime([ScopedMethod()])
    runtime.events.on("*", lambda event: states.append((event.name, payment_flow_active())))
    try:
        await runtime.call_mcp_tool(call_tool, "premium")
    finally:
        await runtime.aclose()

    assert states == [
        ("session", False),
        ("challenge.received", True),
        ("method", True),
        ("credential.created", True),
        ("session", False),
        ("payment.response", True),
    ]


@pytest.mark.asyncio
async def test_unexpired_offer_wins_over_compatible_expired_offer() -> None:
    method = Method()
    offered = payment_error(
        challenge("expired", expires="2020-01-01T00:00:00Z"),
        challenge("current"),
    )
    session = Session(offered, Result())
    runtime = PaymentRuntime([method])
    try:
        await runtime.call_mcp_tool(session.call_tool, "premium")
    finally:
        await runtime.aclose()

    credential = session.calls[1][1]["meta"][META_CREDENTIAL]
    assert credential["challenge"]["id"] == "current"


@pytest.mark.asyncio
async def test_expired_challenge_reports_selected_offer_without_paying() -> None:
    method = Method()
    failed: list[dict[str, Any]] = []
    session = Session(payment_error(challenge(expires="2020-01-01T00:00:00Z")))
    runtime = PaymentRuntime([method])
    runtime.events.on("payment.failed", failed.append)
    try:
        with pytest.raises(ValueError, match="Challenge expired"):
            await runtime.call_mcp_tool(session.call_tool, "premium")
    finally:
        await runtime.aclose()

    assert failed[0]["challenge"].id == "challenge-1"
    assert failed[0]["credential"] is None
    assert method.calls == 0


@pytest.mark.asyncio
async def test_disallowed_or_invalid_realm_fails_without_paying() -> None:
    for realm in ("other.example", "https://[malformed"):
        method = Method()
        session = Session(payment_error(challenge(realm=realm)))
        runtime = PaymentRuntime([method], allowed_origins=["https://api.example.com"])
        try:
            with pytest.raises(ValueError, match="disallowed"):
                await runtime.call_mcp_tool(session.call_tool, "premium")
        finally:
            await runtime.aclose()
        assert method.calls == 0
        assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_unknown_operation_is_session_scoped() -> None:
    method = Method()
    first = Session(payment_error(challenge("first")), TimeoutError("lost"))
    second = Session(payment_error(challenge("second")), Result())
    runtime = PaymentRuntime([method])
    try:
        with pytest.raises(PaymentOutcomeUnknownError):
            await runtime.call_mcp_tool(first.call_tool, "premium", {"query": "same"})

        result = await runtime.call_mcp_tool(second.call_tool, "premium", {"query": "same"})
    finally:
        await runtime.aclose()

    assert isinstance(result, Result)
    assert method.calls == 2


@pytest.mark.asyncio
async def test_unknown_operation_blocks_repayment_until_reset() -> None:
    method = Method()
    session = Session(
        payment_error(challenge("first")),
        payment_error(challenge("retry")),
        payment_error(challenge("second")),
        payment_error(challenge("after-reset")),
        Result(),
    )
    runtime = PaymentRuntime([method])
    try:
        with pytest.raises(PaymentOutcomeUnknownError):
            await runtime.call_mcp_tool(session.call_tool, "premium", {"query": "same"})
        with pytest.raises(PaymentOutcomeUnknownError):
            await runtime.call_mcp_tool(session.call_tool, "premium", {"query": "same"})
        with pytest.raises(ValueError, match="externally reconciled"):
            runtime.reset_unknown_outcomes(reconciled=False)

        runtime.reset_unknown_outcomes(reconciled=True)
        result = await runtime.call_mcp_tool(session.call_tool, "premium", {"query": "same"})
    finally:
        await runtime.aclose()

    assert isinstance(result, Result)
    assert method.calls == 2
    assert len(session.calls) == 5


@pytest.mark.asyncio
async def test_concurrent_same_challenge_only_creates_one_credential() -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingMethod(Method):
        async def create_credential(self, challenge: Challenge) -> Credential:
            entered.set()
            await asyncio.to_thread(release.wait)
            return await super().create_credential(challenge)

    method = BlockingMethod()
    first = Session(payment_error(), Result())
    second = Session(payment_error(), Result())
    runtime = PaymentRuntime([method])
    first_call = asyncio.create_task(runtime.call_mcp_tool(first.call_tool, "premium"))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        with pytest.raises(PaymentOutcomeUnknownError):
            await runtime.call_mcp_tool(second.call_tool, "premium")
        release.set()
        assert isinstance(await first_call, Result)
    finally:
        release.set()
        await runtime.aclose()

    assert method.calls == 1
    assert len(first.calls) == 2
    assert len(second.calls) == 1


@pytest.mark.asyncio
async def test_close_waits_for_committed_retry() -> None:
    retry_started = asyncio.Event()
    retry_release = asyncio.Event()
    calls = 0

    async def call_tool(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise payment_error()
        retry_started.set()
        await retry_release.wait()
        return Result()

    runtime = PaymentRuntime([Method()])
    request = asyncio.create_task(runtime.call_mcp_tool(call_tool, "premium"))
    await asyncio.wait_for(retry_started.wait(), 1)
    close = asyncio.create_task(runtime.aclose())
    await asyncio.sleep(0)
    assert not close.done()

    retry_release.set()
    assert isinstance(await request, Result)
    await asyncio.wait_for(close, 1)


@pytest.mark.asyncio
async def test_mcp_client_runtime_ownership_and_caller_loop_compatibility() -> None:
    caller_loop = asyncio.get_running_loop()
    method = Method()
    session = Session(payment_error(), Result())

    async with McpClient(session, methods=[method]) as client:
        await client.call_tool("premium")
        assert client._runtime._bridge._thread is None

    assert method.loops == [caller_loop]
    assert client._runtime._bridge._closed

    runtime = PaymentRuntime([Method()])
    borrowed = McpClient(Session(payment_error(), Result()), runtime=runtime)
    await borrowed.call_tool("premium")
    thread = runtime._bridge._thread
    assert thread is not None and thread.is_alive()
    await borrowed.aclose()
    assert thread.is_alive()
    await runtime.aclose()


@pytest.mark.asyncio
async def test_mcp_client_sync_close_requires_synchronous_context() -> None:
    client = McpClient(Session(), methods=[])
    with pytest.raises(RuntimeError, match="await client.aclose"):
        client.close()
    await client.aclose()


def test_mcp_client_sync_close_outside_event_loop() -> None:
    client = McpClient(Session(), methods=[])
    client.close()
    with pytest.raises(RuntimeError, match="closed"):
        client._runtime.start()


def test_mcp_client_requires_exactly_one_method_source() -> None:
    runtime = PaymentRuntime([])
    with pytest.raises(ValueError, match="methods or runtime"):
        McpClient(Session())
    with pytest.raises(ValueError, match="either methods or runtime"):
        McpClient(Session(), [], runtime=runtime)
    runtime.close()


def test_mcp_realm_policy_does_not_broaden_http_policy() -> None:
    runtime = PaymentRuntime(
        [],
        allowed_origins=["https://bücher.example", "mcp.example.com"],
    )
    try:
        assert runtime._allowed.mcp_realm("xn--bcher-kva.example")
        assert runtime._allowed.mcp_realm("mcp.example.com")
        assert runtime.allows_http_payment(httpx.URL("https://xn--bcher-kva.example"))
        assert not runtime.allows_http_payment(httpx.URL("https://mcp.example.com"))
        assert not runtime._allowed.mcp_realm("https://bücher.example:8443")
    finally:
        runtime.close()


def test_send_boundary_rechecks_unknown_operation_and_bounded_circuit() -> None:
    runtime = PaymentRuntime([], max_unknown_outcomes=1)

    async def endpoint(*_args: Any, **_kwargs: Any) -> None:
        return None

    first = runtime._begin_mcp_payment(
        SimpleNamespace(id="first", realm="api.example.com"),
        endpoint,
        "premium",
        {},
    )
    raced = runtime._begin_mcp_payment(
        SimpleNamespace(id="raced", realm="api.example.com"),
        endpoint,
        "premium",
        {},
    )
    runtime._mark_mcp_payment_sent(first)
    runtime._mark_mcp_payment_unknown(first, TimeoutError("lost"))
    with pytest.raises(PaymentOutcomeUnknownError):
        runtime._mark_mcp_payment_sent(raced)
    assert not runtime._mcp_challenges

    second = runtime._begin_mcp_payment(
        SimpleNamespace(id="second", realm="api.example.com"),
        object(),
        "other",
        {},
    )
    runtime._mark_mcp_payment_sent(second)
    runtime._mark_mcp_payment_unknown(second, TimeoutError("also lost"))
    assert runtime._mcp_unknown_circuit is not None
    with pytest.raises(PaymentOutcomeUnknownError):
        runtime._begin_mcp_payment(
            SimpleNamespace(id="fresh", realm="api.example.com"),
            endpoint,
            "fresh",
            {},
        )

    runtime.reset_unknown_outcomes(reconciled=True)
    assert runtime._mcp_unknown_circuit is None
    runtime.close()


def test_colliding_sent_operations_keep_each_challenge_tombstone() -> None:
    runtime = PaymentRuntime([])

    async def endpoint(*_args: Any, **_kwargs: Any) -> None:
        return None

    attempts = [
        runtime._begin_mcp_payment(
            SimpleNamespace(id=challenge_id, realm="api.example.com"),
            endpoint,
            "premium",
            {},
        )
        for challenge_id in ("first", "second")
    ]
    for attempt in attempts:
        runtime._mark_mcp_payment_sent(attempt)
    for attempt in attempts:
        runtime._mark_mcp_payment_unknown(attempt, TimeoutError(f"{attempt.challenge.id} lost"))

    assert len(runtime._mcp_unknown_operations) == 1
    assert {tombstone.challenge.id for tombstone in runtime._mcp_unknown_challenges.values()} == {
        "first",
        "second",
    }
    assert not runtime._mcp_challenges
    runtime.close()
