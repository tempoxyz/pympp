"""Tests for the shared payment runtime."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from mpp import Challenge, ChallengeEcho, Credential
from mpp.extensions.mcp import (
    META_CREDENTIAL,
    McpClient,
    PaymentOutcomeUnknownError,
)
from mpp.runtime import Method, PaymentRuntime, payment_flow_active


class MockMethod:
    name = "tempo"
    _intents = {"charge": True}

    def __init__(self) -> None:
        self.create_credential = AsyncMock(
            return_value=Credential(
                challenge=ChallengeEcho(
                    id="test-id",
                    realm="example.com",
                    method="tempo",
                    intent="charge",
                    request="e30",
                ),
                payload={"hash": "0xabc"},
                source="0x1234",
            )
        )


class MockTransport(httpx.AsyncBaseTransport):
    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0)


class FakeCallToolResult:
    def __init__(self, text: str = "ok", meta: dict[str, Any] | None = None) -> None:
        self.content = [{"type": "text", "text": text}]
        self.isError = False
        self.meta = meta


class FakeMcpError(Exception):
    def __init__(self, code: int, data: Any = None) -> None:
        super().__init__("mcp error")
        self.code = code
        self.data = data


class FakeClientSession:
    def __init__(self, side_effects: list[Any]) -> None:
        self.side_effects = side_effects
        self.calls: list[tuple[str, dict[str, Any] | None, tuple[Any, ...], dict[str, Any]]] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        self.calls.append((name, arguments, args, kwargs))
        item = self.side_effects.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def payment_challenge_header() -> str:
    challenge = Challenge(id="test-id", method="tempo", intent="charge", request={})
    return challenge.to_www_authenticate("example.com")


def mcp_payment_error(
    *,
    realm: str = "example.com",
    expires: str | None = None,
) -> FakeMcpError:
    error = FakeMcpError(
        -32042,
        data={
            "challenges": [
                {
                    "id": "test-id",
                    "realm": realm,
                    "method": "tempo",
                    "intent": "charge",
                    "request": {"amount": "1000"},
                }
            ]
        },
    )
    if expires is not None:
        error.data["challenges"][0]["expires"] = expires
    return error


class TestHttpxRuntime:
    @pytest.mark.parametrize(
        ("allowed", "url"),
        [
            ("HTTPS://EXAMPLE.COM:443/path", "https://example.com/resource"),
            ("https://[2001:DB8::1]:443/path", "https://[2001:db8::1]/resource"),
            ("https://bücher.example", "https://xn--bcher-kva.example/resource"),
            ("https://xn--bcher-kva.example", "https://bücher.example/resource"),
        ],
    )
    def test_allowed_origins_are_normalized(self, allowed: str, url: str) -> None:
        runtime = PaymentRuntime([], allowed_origins=[allowed])

        assert runtime.allows_http_payment(httpx.URL(url))

    def test_mcp_url_realm_uses_normalized_origin(self) -> None:
        runtime = PaymentRuntime([], allowed_origins=["HTTPS://EXAMPLE.COM:443/path"])

        assert runtime._allowed.mcp_realm("https://example.com/tool")

    def test_http_url_allowlist_accepts_matching_hostname_mcp_realm(self) -> None:
        runtime = PaymentRuntime([], allowed_origins=["https://api.example.com"])

        assert runtime._allowed.mcp_realm("api.example.com")
        assert not runtime._allowed.mcp_realm("http://api.example.com:9999")

    @pytest.mark.parametrize(
        ("allowed", "realm"),
        [
            ("https://bücher.example", "xn--bcher-kva.example"),
            ("https://xn--bcher-kva.example", "bücher.example"),
            ("bücher.example", "https://xn--bcher-kva.example"),
            ("xn--bcher-kva.example", "https://bücher.example"),
        ],
    )
    def test_mcp_realms_use_idna_normalized_hosts(self, allowed: str, realm: str) -> None:
        runtime = PaymentRuntime([], allowed_origins=[allowed])

        assert runtime._allowed.mcp_realm(realm)

    def test_bare_mcp_realm_does_not_authorize_http(self) -> None:
        runtime = PaymentRuntime([], allowed_origins=["api.example.com"])

        assert runtime._allowed.mcp_realm("api.example.com")
        assert not runtime.allows_http_payment(httpx.URL("https://api.example.com"))

    @pytest.mark.asyncio
    async def test_runtime_wrap_async_client_without_global_hook(self) -> None:
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": payment_challenge_header()}),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        runtime = PaymentRuntime([MockMethod()])
        client = runtime.wrap_async_client(httpx.AsyncClient(transport=inner))
        try:
            response = await client.get("https://example.com/paid")
        finally:
            await client.aclose()

        assert response.status_code == 200
        assert len(inner.requests) == 2
        assert inner.requests[1].headers["authorization"].startswith("Payment ")

    @pytest.mark.asyncio
    async def test_runtime_wrappers_pay_before_httpx_response_hooks(self) -> None:
        sync_calls = 0
        async_calls = 0
        seen: list[tuple[str, int]] = []

        def sync_handler(_request: httpx.Request) -> httpx.Response:
            nonlocal sync_calls
            sync_calls += 1
            if sync_calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": payment_challenge_header()},
                )
            return httpx.Response(200)

        async def async_handler(_request: httpx.Request) -> httpx.Response:
            nonlocal async_calls
            async_calls += 1
            if async_calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": payment_challenge_header()},
                )
            return httpx.Response(200)

        def sync_hook(response: httpx.Response) -> None:
            seen.append(("sync", response.status_code))
            response.raise_for_status()

        async def async_hook(response: httpx.Response) -> None:
            seen.append(("async", response.status_code))
            response.raise_for_status()

        runtime = PaymentRuntime([MockMethod()])
        sync_client = runtime.wrap_client(
            httpx.Client(
                transport=httpx.MockTransport(sync_handler),
                event_hooks={"response": [sync_hook]},
            )
        )
        async_client = runtime.wrap_async_client(
            httpx.AsyncClient(
                transport=httpx.MockTransport(async_handler),
                event_hooks={"response": [async_hook]},
            )
        )
        try:
            sync_response = sync_client.get("https://example.com/sync")
            async_response = await async_client.get("https://example.com/async")
        finally:
            sync_client.close()
            await async_client.aclose()
            runtime.close()

        assert sync_response.status_code == async_response.status_code == 200
        assert seen == [("sync", 200), ("async", 200)]

    @pytest.mark.asyncio
    async def test_disallowed_http_origin_does_not_retry_payment(self) -> None:
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": payment_challenge_header()}),
            ]
        )
        method = MockMethod()
        runtime = PaymentRuntime(
            [method],
            allowed_origins=["https://other.example"],
        )
        client = runtime.wrap_async_client(httpx.AsyncClient(transport=inner))
        try:
            response = await client.get("https://example.com/paid")
        finally:
            await client.aclose()

        assert response.status_code == 402
        assert len(inner.requests) == 1
        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_redirected_402_uses_challenged_origin_policy(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.host == "allowed.example":
                return httpx.Response(302, headers={"location": "https://evil.example/paid"})
            return httpx.Response(
                402,
                headers={"www-authenticate": payment_challenge_header()},
            )

        method = MockMethod()
        runtime = PaymentRuntime([method], allowed_origins=["https://allowed.example"])
        client = runtime.wrap_async_client(
            httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)
        )
        try:
            response = await client.get("https://allowed.example/start")
        finally:
            await client.aclose()

        assert response.status_code == 402
        assert [request.url.host for request in requests] == ["allowed.example", "evil.example"]
        method.create_credential.assert_not_called()


class TestRuntimeLifecycle:
    @pytest.mark.asyncio
    async def test_factory_lifecycle_uses_one_owned_loop_for_sync_and_async(self) -> None:
        loops: list[asyncio.AbstractEventLoop] = []
        events: list[str] = []

        class LoopBoundMethod:
            name = "tempo"
            _intents = {"charge": True}

            def __init__(self) -> None:
                self.loop = asyncio.get_running_loop()
                self.ready = self.loop.create_future()
                self.loop.call_soon(self.ready.set_result, None)

            async def create_credential(self, challenge: Challenge) -> Credential:
                loops.append(asyncio.get_running_loop())
                await self.ready
                return Credential(challenge=challenge.to_echo(), payload={"ok": True})

        @asynccontextmanager
        async def factory():
            events.append("enter")
            method = LoopBoundMethod()
            loops.append(method.loop)
            try:
                yield method
            finally:
                loops.append(asyncio.get_running_loop())
                events.append("exit")

        caller_loop = asyncio.get_running_loop()
        async with PaymentRuntime(method_factories=[factory]) as runtime:
            method = runtime.methods[0]
            await runtime.create_credential(
                Challenge(id="async", method="tempo", intent="charge", request={}),
                method,
            )
            await asyncio.to_thread(
                runtime.create_credential_sync,
                Challenge(id="sync", method="tempo", intent="charge", request={}),
                method,
            )
            thread = runtime._bridge._thread
            assert thread is not None and thread is not threading.current_thread()

        assert events == ["enter", "exit"]
        assert len(set(loops)) == 1
        assert loops[0] is not caller_loop
        assert thread is not None and not thread.is_alive()
        with pytest.raises(RuntimeError, match="closed"):
            runtime.start()

    @pytest.mark.asyncio
    async def test_concurrent_start_is_single_flight_and_cancellation_safe(self) -> None:
        calls = 0

        async def factory() -> MockMethod:
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.05)
            return MockMethod()

        runtime = PaymentRuntime(method_factories=[factory])
        first = asyncio.create_task(runtime.astart())
        second = asyncio.create_task(runtime.astart())
        await asyncio.sleep(0.01)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert await second is runtime
        assert calls == 1
        await runtime.aclose()

    @pytest.mark.asyncio
    async def test_cancelled_async_context_entry_closes_started_runtime(self) -> None:
        events: list[str] = []
        entered = threading.Event()

        @asynccontextmanager
        async def slow_factory() -> AsyncIterator[Method]:
            events.append("enter")
            entered.set()
            await asyncio.sleep(0.05)
            try:
                yield MockMethod()
            finally:
                events.append("exit")

        runtime = PaymentRuntime(method_factories=[slow_factory])

        async def use_runtime() -> None:
            async with runtime:
                raise AssertionError("cancelled entry must not reach the context body")

        task = asyncio.create_task(use_runtime())
        assert await asyncio.to_thread(entered.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        thread = runtime._bridge._thread
        assert events == ["enter", "exit"]
        assert runtime._state == "closed"
        assert thread is not None and not thread.is_alive()

    @pytest.mark.asyncio
    async def test_cancelled_async_context_exit_finishes_runtime_close(self) -> None:
        events: list[str] = []
        exit_started = threading.Event()

        @asynccontextmanager
        async def slow_factory() -> AsyncIterator[Method]:
            events.append("enter")
            try:
                yield MockMethod()
            finally:
                exit_started.set()
                await asyncio.sleep(0.05)
                events.append("exit")

        runtime = PaymentRuntime(method_factories=[slow_factory])

        async def use_runtime() -> None:
            async with runtime:
                pass

        task = asyncio.create_task(use_runtime())
        assert await asyncio.to_thread(exit_started.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        thread = runtime._bridge._thread
        assert events == ["enter", "exit"]
        assert runtime._state == "closed"
        assert thread is not None and not thread.is_alive()

    def test_sync_context_manager_and_close_before_start(self) -> None:
        calls = 0

        def factory() -> MockMethod:
            nonlocal calls
            calls += 1
            return MockMethod()

        unused = PaymentRuntime(method_factories=[factory])
        unused.close()
        assert calls == 0

        with PaymentRuntime(method_factories=[factory]) as runtime:
            assert runtime.methods
        assert calls == 1
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_factory_failure_unwinds_entered_methods_and_stops_loop(self) -> None:
        events: list[str] = []

        @asynccontextmanager
        async def managed():
            events.append("enter")
            try:
                yield MockMethod()
            finally:
                events.append("exit")

        async def fail() -> MockMethod:
            raise ValueError("factory failed")

        runtime = PaymentRuntime(method_factories=[managed, fail])
        with pytest.raises(ValueError, match="factory failed"):
            runtime.start()

        assert events == ["enter", "exit"]
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()
        with pytest.raises(RuntimeError, match="failed to start"):
            runtime.start()

    def test_thread_start_failure_closes_runtime_without_waiting(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runtime = PaymentRuntime([])

        def fail_start(_thread: threading.Thread) -> None:
            raise OSError("thread unavailable")

        monkeypatch.setattr(threading.Thread, "start", fail_start)
        with pytest.raises(RuntimeError, match="background loop failed") as exc_info:
            runtime.start()

        assert isinstance(exc_info.value.__cause__, OSError)
        assert runtime._state == "closed"
        assert runtime._bridge._ready.is_set()
        assert runtime._bridge._stopped.is_set()

    @pytest.mark.parametrize("stage", ["new", "set"])
    def test_loop_initialization_failure_is_published_and_stopped(
        self,
        monkeypatch: pytest.MonkeyPatch,
        stage: str,
    ) -> None:
        runtime = PaymentRuntime([])
        loop: asyncio.AbstractEventLoop | None = None
        shutdown_asyncgens = AsyncMock()

        def fail() -> None:
            raise OSError(f"{stage} loop failed")

        if stage == "new":
            monkeypatch.setattr(asyncio, "new_event_loop", fail)
        else:
            original_new_event_loop = asyncio.new_event_loop

            def capture_loop() -> asyncio.AbstractEventLoop:
                nonlocal loop
                loop = original_new_event_loop()
                monkeypatch.setattr(loop, "shutdown_asyncgens", shutdown_asyncgens)
                return loop

            monkeypatch.setattr(asyncio, "new_event_loop", capture_loop)
            monkeypatch.setattr(asyncio, "set_event_loop", lambda _loop: fail())

        with pytest.raises(RuntimeError, match="background loop failed") as exc_info:
            runtime.start()

        assert isinstance(exc_info.value.__cause__, OSError)
        assert runtime._state == "closed"
        assert runtime._bridge._ready.is_set()
        assert runtime._bridge._stopped.is_set()
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()
        assert runtime._bridge._loop is None
        assert loop is None or loop.is_closed()
        shutdown_asyncgens.assert_not_called()

    def test_shutdown_runs_all_cleanup_and_reraises_first_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runtime = PaymentRuntime([]).start()
        original_close = runtime._bridge.close
        closed = False

        def fail_cancel() -> None:
            raise ValueError("first cleanup failure")

        def close_then_fail() -> None:
            nonlocal closed
            original_close()
            closed = True
            raise RuntimeError("later cleanup failure")

        monkeypatch.setattr(runtime._bridge, "cancel_pending", fail_cancel)
        monkeypatch.setattr(runtime._bridge, "close", close_then_fail)

        with pytest.raises(ValueError, match="first cleanup failure"):
            runtime.close()

        assert closed
        assert runtime._state == "closed"
        assert runtime._bridge._stopped.is_set()
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_loop_cleanup_failure_is_published_after_thread_stops(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runtime = PaymentRuntime([]).start()
        loop = runtime._bridge._loop
        assert loop is not None

        async def fail_shutdown(_loop: Any) -> None:
            raise OSError("async generator cleanup failed")

        monkeypatch.setattr(type(loop), "shutdown_asyncgens", fail_shutdown)
        with pytest.raises(OSError, match="async generator cleanup failed"):
            runtime.close()

        assert runtime._state == "closed"
        assert runtime._bridge._stopped.is_set()
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_methods_and_factories_are_mutually_exclusive(self) -> None:
        with pytest.raises(ValueError, match="either methods or method_factories"):
            PaymentRuntime([], method_factories=[MockMethod])

    @pytest.mark.parametrize("value", [0, -1, True, 1.5])
    def test_unknown_outcome_limit_must_be_positive(self, value: Any) -> None:
        with pytest.raises(ValueError, match="positive integer"):
            PaymentRuntime([], max_unknown_outcomes=value)

    @pytest.mark.parametrize("async_close", [False, True])
    @pytest.mark.asyncio
    async def test_close_from_owned_loop_event_is_deferred(
        self,
        async_close: bool,
    ) -> None:
        events: list[str] = []

        class ManagedMethod:
            name = "tempo"
            _intents = {"charge": True}

            async def create_credential(self, challenge: Challenge) -> Credential:
                events.append("credential")
                return Credential(challenge=challenge.to_echo(), payload={"ok": True})

        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            events.append("enter")
            try:
                yield ManagedMethod()
            finally:
                events.append("exit")

        runtime = PaymentRuntime(method_factories=[factory])
        await runtime.astart()

        if async_close:

            async def async_close_from_event(_payload: Any) -> None:
                events.append("close")
                await runtime.aclose()
                events.append("closed-callback")

            close_from_event = async_close_from_event
        else:

            def sync_close_from_event(_payload: Any) -> None:
                events.append("close")
                runtime.close()
                events.append("closed-callback")

            close_from_event = sync_close_from_event

        runtime.events.on("challenge.received", close_from_event)
        credential = await asyncio.wait_for(
            runtime.create_credential(
                Challenge(id="close", method="tempo", intent="charge", request={}),
                runtime.methods[0],
            ),
            1,
        )

        assert credential.payload == {"ok": True}
        assert events == ["enter", "close", "closed-callback", "credential", "exit"]
        assert runtime._state == "closed"
        assert runtime._bridge._thread is not None
        assert not runtime._bridge._thread.is_alive()

    def test_external_close_cancels_method_before_lifecycle_exit(self) -> None:
        events: list[str] = []
        started = threading.Event()

        class BlockingMethod:
            name = "tempo"
            _intents = {"charge": True}

            async def create_credential(self, challenge: Challenge) -> Credential:
                events.append("credential-start")
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    events.append("credential-finally")
                raise AssertionError(f"unexpected release for {challenge.id}")

        @asynccontextmanager
        async def factory() -> AsyncIterator[Method]:
            events.append("enter")
            try:
                yield BlockingMethod()
            finally:
                events.append("exit")

        runtime = PaymentRuntime(method_factories=[factory])
        runtime.start()
        errors: list[BaseException] = []

        def create_credential() -> None:
            try:
                runtime.create_credential_sync(
                    Challenge(id="cancel", method="tempo", intent="charge", request={}),
                    runtime.methods[0],
                )
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=create_credential)
        worker.start()
        assert started.wait(1)

        runtime.close()
        worker.join(timeout=1)

        assert not worker.is_alive()
        assert len(errors) == 1
        assert type(errors[0]).__name__ == "CancelledError"
        assert events == ["enter", "credential-start", "credential-finally", "exit"]

    @pytest.mark.parametrize("async_close", [False, True])
    def test_close_during_method_exit_does_not_deadlock(self, async_close: bool) -> None:
        events: list[str] = []
        runtime_holder: dict[str, PaymentRuntime] = {}

        class ManagedMethod:
            name = "tempo"

            async def create_credential(self, challenge: Challenge) -> Credential:
                raise AssertionError(f"unexpected credential for {challenge.id}")

            async def __aenter__(self) -> ManagedMethod:
                events.append("enter")
                return self

            async def __aexit__(self, *_args: Any) -> None:
                events.append("exit-start")
                runtime = runtime_holder["runtime"]
                if async_close:
                    await runtime.aclose()
                else:
                    runtime.close()
                events.append("exit-end")

        runtime = PaymentRuntime(method_factories=[ManagedMethod])
        runtime_holder["runtime"] = runtime
        runtime.start()
        errors: list[BaseException] = []

        def close() -> None:
            try:
                runtime.close()
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=close, daemon=True)
        worker.start()
        worker.join(timeout=1)

        assert not worker.is_alive()
        assert not errors
        assert events == ["enter", "exit-start", "exit-end"]
        assert runtime._state == "closed"

    @pytest.mark.asyncio
    async def test_caller_loop_cancellation_finishes_deferred_close(self) -> None:
        from mpp.runtime import _CallerLoopRuntime

        runtime = _CallerLoopRuntime([MockMethod()])
        started = asyncio.Event()
        finalized = asyncio.Event()

        async def operation() -> None:
            runtime.close()
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                finalized.set()

        task = asyncio.create_task(runtime.run_async(operation()))
        await asyncio.wait_for(started.wait(), 1)
        assert runtime._state == "closing"

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert finalized.is_set()
        assert runtime._state == "closed"

    @pytest.mark.asyncio
    async def test_inherited_paid_lease_counts_child_until_it_exits(self) -> None:
        runtime = PaymentRuntime([])
        entered = asyncio.Event()
        release = asyncio.Event()

        async def child() -> None:
            with runtime._paid_operation():
                entered.set()
                await release.wait()

        with runtime._paid_operation():
            task = asyncio.create_task(child())
            await asyncio.wait_for(entered.wait(), 1)

        assert runtime._active_paid_operations == 1
        close = asyncio.create_task(asyncio.to_thread(runtime.close))
        await asyncio.sleep(0.01)
        assert not close.done()

        release.set()
        await asyncio.wait_for(task, 1)
        await asyncio.wait_for(close, 1)
        assert runtime._state == "closed"

    @pytest.mark.asyncio
    async def test_deferred_close_waits_for_inherited_runtime_lease_child(self) -> None:
        runtime = PaymentRuntime([])
        entered = asyncio.Event()
        release = asyncio.Event()

        async def child() -> None:
            with runtime._runtime_operation():
                entered.set()
                await release.wait()

        with runtime._runtime_operation():
            task = asyncio.create_task(child())
            await asyncio.wait_for(entered.wait(), 1)
            runtime.close()

        assert runtime._state == "closing"
        assert runtime._active_runtime_operations == 1
        release.set()
        await asyncio.wait_for(task, 1)
        assert runtime._state == "closed"

    @pytest.mark.asyncio
    async def test_payment_flow_marker_expires_in_detached_child(self) -> None:
        runtime = PaymentRuntime([])
        child: asyncio.Task[None] | None = None
        started = asyncio.Event()
        release = asyncio.Event()
        states: list[bool] = []

        class SpawningMethod:
            name = "tempo"
            intents = MappingProxyType({"charge": True})

            async def create_credential(self, challenge: Challenge) -> Credential:
                nonlocal child

                async def detached() -> None:
                    states.append(payment_flow_active())
                    started.set()
                    await release.wait()
                    states.append(payment_flow_active())

                child = asyncio.create_task(detached())
                await started.wait()
                return Credential(challenge=challenge.to_echo(), payload={"ok": True})

        method = SpawningMethod()
        await runtime.create_credential(
            Challenge(id="flow", method="tempo", intent="charge", request={}),
            method,
        )

        async def finish_child() -> None:
            release.set()
            assert child is not None
            await child

        await runtime.run_async(finish_child())
        await runtime.aclose()
        assert states == [True, False]


class TestUncertaintyState:
    def test_http_unknown_outcomes_trip_bounded_fail_closed_circuit(self) -> None:
        runtime = PaymentRuntime([], max_unknown_outcomes=2)

        for index in range(3):
            challenge = Challenge(
                id=f"unknown-{index}",
                method="tempo",
                intent="charge",
                request={},
            )
            request = httpx.Request(
                "POST",
                f"https://example.com/pay/{index}",
                content=str(index),
            )
            attempt = runtime._begin_http_payment(challenge, request)
            runtime._mark_http_payment_sent(attempt, request)
            runtime._mark_http_payment_unknown(attempt, TimeoutError("response lost"))

        assert len(runtime._http_unknown_challenges) == 2
        assert len(runtime._http_unknown_operations) == 2
        assert runtime._http_unknown_circuit is not None

        fresh = Challenge(id="fresh", method="tempo", intent="charge", request={})
        with pytest.raises(PaymentOutcomeUnknownError, match="outcome is unknown"):
            runtime._begin_http_payment(
                fresh,
                httpx.Request("POST", "https://example.com/pay/fresh"),
            )
        with pytest.raises(ValueError, match="externally reconciled"):
            runtime.reset_unknown_outcomes(reconciled=False)

        runtime.reset_unknown_outcomes(reconciled=True)

        assert not runtime._http_unknown_challenges
        assert not runtime._http_unknown_operations
        assert runtime._http_unknown_circuit is None
        attempt = runtime._begin_http_payment(
            fresh,
            httpx.Request("POST", "https://example.com/pay/fresh"),
        )
        runtime._discard_http_payment(attempt)
        runtime.close()

    def test_mcp_unknown_outcomes_trip_bounded_fail_closed_circuit(self) -> None:
        runtime = PaymentRuntime([], max_unknown_outcomes=2)

        async def endpoint(*_args: Any, **_kwargs: Any) -> None:
            return None

        for index in range(3):
            challenge = SimpleNamespace(id=f"unknown-{index}", realm="example.com")
            attempt = runtime._begin_mcp_payment(
                challenge,
                endpoint,
                f"tool-{index}",
                {"index": index},
            )
            runtime._mark_mcp_payment_sent(attempt)
            runtime._mark_mcp_payment_unknown(attempt, TimeoutError("response lost"))

        assert len(runtime._mcp_unknown_challenges) == 2
        assert len(runtime._mcp_unknown_operations) == 2
        assert runtime._mcp_unknown_circuit is not None

        fresh = SimpleNamespace(id="fresh", realm="example.com")
        with pytest.raises(PaymentOutcomeUnknownError, match="outcome is unknown"):
            runtime._begin_mcp_payment(fresh, endpoint, "fresh-tool", {})

        runtime.reset_unknown_outcomes(reconciled=True)

        assert not runtime._mcp_unknown_challenges
        assert not runtime._mcp_unknown_operations
        assert runtime._mcp_unknown_circuit is None
        attempt = runtime._begin_mcp_payment(fresh, endpoint, "fresh-tool", {})
        runtime._discard_mcp_payment(attempt)
        runtime.close()

    def test_close_preserves_tombstone_for_sent_http_attempt(self) -> None:
        challenge = Challenge(id="closing", method="tempo", intent="charge", request={})
        request = httpx.Request("POST", "https://example.com/pay")
        retry = httpx.Request("POST", "https://example.com/pay")
        runtime = PaymentRuntime([])
        attempt = runtime._begin_http_payment(challenge, request)
        runtime._mark_http_payment_sent(attempt, retry)

        runtime.close()

        replacement = PaymentRuntime([])
        try:
            with pytest.raises(PaymentOutcomeUnknownError, match="outcome is unknown"):
                replacement._begin_http_payment(challenge, request)
            with pytest.raises(PaymentOutcomeUnknownError, match="outcome is unknown"):
                replacement._begin_http_payment(challenge, retry)
        finally:
            replacement.close()

    def test_http_attempt_markers_are_cleared_after_success_and_discard(self) -> None:
        runtime = PaymentRuntime([])
        challenge = Challenge(id="marker", method="tempo", intent="charge", request={})
        request = httpx.Request("POST", "https://example.com/pay")
        retry = httpx.Request("POST", "https://example.com/pay")
        attempt = runtime._begin_http_payment(challenge, request)
        runtime._mark_http_payment_sent(attempt, retry)

        runtime._mark_http_response_body_complete(attempt)
        runtime._mark_http_send_complete(attempt)

        assert "mpp.payment_attempt" not in request.extensions
        assert "mpp.payment_attempt" not in retry.extensions

        discarded = runtime._begin_http_payment(
            Challenge(id="discard", method="tempo", intent="charge", request={}),
            httpx.Request("POST", "https://example.com/other"),
        )
        discarded.request.extensions["mpp.payment_attempt"] = discarded
        runtime._discard_http_payment(discarded)
        assert "mpp.payment_attempt" not in discarded.request.extensions
        runtime.close()

    def test_colliding_unknown_operations_tombstone_every_sent_challenge(self) -> None:
        runtime = PaymentRuntime([])
        first = Challenge(id="first", method="tempo", intent="charge", request={})
        second = Challenge(id="second", method="tempo", intent="charge", request={})
        first_attempt = runtime._begin_http_payment(
            first,
            httpx.Request("POST", "https://example.com/pay", content=b"same"),
        )
        second_attempt = runtime._begin_http_payment(
            second,
            httpx.Request("POST", "https://example.com/pay", content=b"same"),
        )
        runtime._mark_http_payment_sent(first_attempt, first_attempt.request)
        runtime._mark_http_payment_sent(second_attempt, second_attempt.request)
        runtime._mark_http_payment_unknown(first_attempt, TimeoutError("first lost"))
        runtime._mark_http_payment_unknown(second_attempt, TimeoutError("second lost"))

        assert len(runtime._http_unknown_operations) == 1
        assert len(runtime._http_unknown_challenges) == 2
        assert not runtime._http_challenges

        async def endpoint(*_args: Any, **_kwargs: Any) -> None:
            return None

        first_mcp = runtime._begin_mcp_payment(
            SimpleNamespace(id="first", realm="example.com"),
            endpoint,
            "tool",
            {},
        )
        second_mcp = runtime._begin_mcp_payment(
            SimpleNamespace(id="second", realm="example.com"),
            endpoint,
            "tool",
            {},
        )
        runtime._mark_mcp_payment_sent(first_mcp)
        runtime._mark_mcp_payment_sent(second_mcp)
        runtime._mark_mcp_payment_unknown(first_mcp, TimeoutError("first lost"))
        runtime._mark_mcp_payment_unknown(second_mcp, TimeoutError("second lost"))

        assert len(runtime._mcp_unknown_operations) == 1
        assert len(runtime._mcp_unknown_challenges) == 2
        assert not runtime._mcp_challenges

    def test_http_unknown_tombstone_drops_body_and_traceback_permanently(self) -> None:
        runtime = PaymentRuntime([])
        challenge = Challenge(id="unknown", method="tempo", intent="charge", request={})
        request = httpx.Request("POST", "https://example.com/pay", content=b"x" * 4096)
        retry = httpx.Request("POST", "https://example.com/pay", content=request.content)
        attempt = runtime._begin_http_payment(challenge, request)
        runtime._mark_http_payment_sent(attempt, retry)
        try:
            raise httpx.ReadTimeout("response lost", request=request)
        except httpx.ReadTimeout as cause:
            assert cause.__traceback__ is not None
            tombstone = runtime._mark_http_payment_unknown(attempt, cause)

        assert isinstance(tombstone.cause, httpx.ReadTimeout)
        assert tombstone.cause.__traceback__ is None
        assert tombstone.request is not request
        assert tombstone.request.content == b""
        assert not runtime._http_challenges
        assert request.extensions["mpp.payment_attempt"] is tombstone
        assert retry.extensions["mpp.payment_attempt"] is tombstone
        assert not hasattr(tombstone, "runtime")

        with pytest.raises(PaymentOutcomeUnknownError):
            runtime._begin_http_payment(
                challenge,
                httpx.Request("POST", "https://example.com/pay", content=b"x" * 4096),
            )
        runtime.close()

        assert not runtime._http_unknown_challenges
        assert not runtime._http_unknown_operations
        with pytest.raises(RuntimeError, match="closed"):
            with runtime._paid_operation():
                raise AssertionError("closed runtime must not enter a paid operation")

    def test_mcp_unknown_tombstone_drops_endpoint_and_traceback(self) -> None:
        runtime = PaymentRuntime([])
        challenge = SimpleNamespace(
            id="unknown",
            realm="example.com",
            method="tempo",
            intent="charge",
        )

        async def endpoint(*_args: Any, **_kwargs: Any) -> None:
            return None

        attempt = runtime._begin_mcp_payment(challenge, endpoint, "tool", {"large": "x" * 4096})
        runtime._mark_mcp_payment_sent(attempt)
        try:
            raise TimeoutError("response lost")
        except TimeoutError as cause:
            assert cause.__traceback__ is not None
            runtime._mark_mcp_payment_unknown(attempt, cause)

        tombstone = next(iter(runtime._mcp_unknown_operations.values()))
        assert isinstance(tombstone.cause, TimeoutError)
        assert tombstone.cause.__traceback__ is None
        assert not hasattr(tombstone, "endpoint")
        assert not runtime._mcp_challenges

        with pytest.raises(PaymentOutcomeUnknownError):
            runtime._begin_mcp_payment(challenge, endpoint, "tool", {"large": "x" * 4096})
        runtime.close()

        assert not runtime._mcp_unknown_challenges
        assert not runtime._mcp_unknown_operations
        with pytest.raises(RuntimeError, match="closed"):
            with runtime._paid_operation():
                raise AssertionError("closed runtime must not enter a paid operation")


class TestMcpRuntime:
    def test_method_public_intents_accepts_any_mapping(self) -> None:
        class PublicMethod:
            name = "tempo"
            intents = MappingProxyType({"subscription": object()})

            async def create_credential(self, challenge: Challenge) -> Credential:
                raise NotImplementedError

        method = PublicMethod()
        runtime = PaymentRuntime([method])
        subscription = Challenge(
            id="subscription",
            method="tempo",
            intent="subscription",
            request={},
        )
        charge = Challenge(id="charge", method="tempo", intent="charge", request={})

        assert runtime.match_challenge([subscription]) == (subscription, method)
        with pytest.raises(ValueError, match="No compatible payment method"):
            runtime.match_challenge([charge])

    def test_method_without_intents_keeps_legacy_charge_fallback(self) -> None:
        class LegacyMethod:
            name = "tempo"

            async def create_credential(self, challenge: Challenge) -> Credential:
                raise NotImplementedError

        method = LegacyMethod()
        runtime = PaymentRuntime([method])
        charge = Challenge(id="charge", method="tempo", intent="charge", request={})

        assert runtime.match_challenge([charge]) == (charge, method)

    def test_invalid_public_intents_capability_is_rejected(self) -> None:
        class InvalidMethod:
            name = "tempo"
            intents: Any = ["charge"]

            async def create_credential(self, challenge: Challenge) -> Credential:
                raise NotImplementedError

        runtime = PaymentRuntime([InvalidMethod()])
        charge = Challenge(id="charge", method="tempo", intent="charge", request={})

        with pytest.raises(TypeError, match="intents must be a Mapping"):
            runtime.match_challenge([charge])

    def test_mcp_does_not_use_legacy_name_only_matching(self) -> None:
        class NameOnlyMethod:
            name = "tempo"

            async def create_credential(self, challenge: Challenge) -> Credential:
                raise NotImplementedError

        runtime = PaymentRuntime([NameOnlyMethod()])
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="subscription",
            request={},
        )

        with pytest.raises(ValueError, match="No compatible payment method"):
            runtime.match_challenge([challenge])

    @pytest.mark.asyncio
    async def test_mcp_client_accepts_runtime_without_methods(self) -> None:
        runtime = PaymentRuntime([MockMethod()])
        session = FakeClientSession([mcp_payment_error(), FakeCallToolResult("paid")])

        client = McpClient(session, runtime=runtime)
        result = await client.call_tool("premium_tool")

        assert client._runtime is runtime
        assert result.result.content[0]["text"] == "paid"

    @pytest.mark.asyncio
    async def test_mcp_client_implicit_runtime_stays_on_caller_loop(self) -> None:
        caller_loop = asyncio.get_running_loop()
        caller_future: asyncio.Future[None] = caller_loop.create_future()
        method = MockMethod()

        async def create_credential(challenge: Challenge) -> Credential:
            await caller_future
            return Credential(
                challenge=challenge.to_echo(),
                payload={"hash": "0xabc"},
            )

        method.create_credential.side_effect = create_credential
        session = FakeClientSession([mcp_payment_error(), FakeCallToolResult("paid")])
        caller_loop.call_later(0.01, caller_future.set_result, None)

        async with McpClient(session, methods=[method]) as client:
            await client.call_tool("premium_tool")
            assert client._runtime._bridge._thread is None

        assert client._runtime._bridge._closed

    @pytest.mark.asyncio
    async def test_mcp_client_does_not_close_injected_runtime(self) -> None:
        runtime = PaymentRuntime([MockMethod()])
        session = FakeClientSession([mcp_payment_error(), FakeCallToolResult("paid")])
        client = McpClient(session, runtime=runtime)
        await client.call_tool("premium_tool")
        thread = runtime._bridge._thread
        assert thread is not None and thread.is_alive()

        await client.aclose()
        assert thread.is_alive()
        await runtime.aclose()
        assert thread.is_alive() is False

    def test_mcp_client_rejects_runtime_with_methods(self) -> None:
        runtime = PaymentRuntime([])

        with pytest.raises(ValueError, match="either methods or runtime"):
            McpClient(FakeClientSession([]), methods=[], runtime=runtime)

    @pytest.mark.asyncio
    async def test_payment_runtime_call_mcp_tool_pays_and_preserves_raw_result(self) -> None:
        raw_result = FakeCallToolResult("paid")
        session = FakeClientSession([mcp_payment_error(), raw_result])
        runtime = PaymentRuntime([MockMethod()])

        result = await runtime.call_mcp_tool(
            session.call_tool,
            "premium_tool",
            {"query": "test"},
            progress_callback="callback",
            meta={"trace_id": "abc"},
        )

        assert result is raw_result
        assert len(session.calls) == 2
        retry_kwargs = session.calls[1][3]
        assert retry_kwargs["progress_callback"] == "callback"
        assert retry_kwargs["meta"]["trace_id"] == "abc"
        assert META_CREDENTIAL in retry_kwargs["meta"]

    @pytest.mark.asyncio
    async def test_close_waits_for_committed_mcp_retry(self) -> None:
        retry_started = asyncio.Event()
        retry_release = asyncio.Event()
        raw_result = FakeCallToolResult("paid")
        calls = 0

        async def call_tool(*_args: Any, **_kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise mcp_payment_error()
            retry_started.set()
            await retry_release.wait()
            return raw_result

        runtime = PaymentRuntime([MockMethod()])
        request = asyncio.create_task(runtime.call_mcp_tool(call_tool, "premium_tool"))
        await asyncio.wait_for(retry_started.wait(), 1)
        close = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.05)
        assert not close.done()

        retry_release.set()
        assert await request is raw_result
        await asyncio.wait_for(close, 1)

    @pytest.mark.asyncio
    async def test_inherited_paid_lease_expires_with_its_owner(self) -> None:
        runtime = PaymentRuntime([])
        release = asyncio.Event()
        ran = False

        async def delayed() -> None:
            nonlocal ran
            await release.wait()

            async def mark_ran() -> None:
                nonlocal ran
                ran = True

            await runtime.run_async(mark_ran())

        with runtime._paid_operation():
            task = asyncio.create_task(delayed())
        runtime.close()
        release.set()

        with pytest.raises(RuntimeError, match="closed"):
            await task
        assert not ran

    @pytest.mark.asyncio
    async def test_disallowed_mcp_realm_does_not_retry_payment(self) -> None:
        method = MockMethod()
        session = FakeClientSession([mcp_payment_error()])
        runtime = PaymentRuntime(
            [method],
            allowed_origins=["other.example"],
        )

        with pytest.raises(ValueError, match="disallowed"):
            await runtime.call_mcp_tool(session.call_tool, "premium_tool", {"query": "test"})

        assert len(session.calls) == 1
        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_expired_mcp_challenge_emits_failure_without_paying(self) -> None:
        method = MockMethod()
        expires = "2020-01-01T00:00:00Z"
        session = FakeClientSession([mcp_payment_error(expires=expires)])
        runtime = PaymentRuntime([method])
        events: list[Any] = []
        runtime.events.on("*", events.append)
        try:
            with pytest.raises(ValueError, match="Challenge expired"):
                await runtime.call_mcp_tool(session.call_tool, "premium_tool")
        finally:
            await runtime.aclose()

        assert len(session.calls) == 1
        method.create_credential.assert_not_called()
        assert [event.name for event in events] == ["payment.failed"]
        assert events[-1].payload["challenge"].expires == expires
        assert events[-1].payload["credential"] is None

    @pytest.mark.parametrize(
        "expires",
        ["", "not-a-timestamp", "2030-01-01T00:00:00", 123],
    )
    @pytest.mark.asyncio
    async def test_invalid_explicit_mcp_expiry_fails_closed(self, expires: Any) -> None:
        method = MockMethod()
        challenge = mcp_payment_error()
        challenge.data["challenges"][0]["expires"] = expires
        session = FakeClientSession([challenge])
        runtime = PaymentRuntime([method])
        try:
            with pytest.raises(ValueError, match="Challenge expired"):
                await runtime.call_mcp_tool(session.call_tool, "premium_tool")
        finally:
            await runtime.aclose()

        assert len(session.calls) == 1
        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_malformed_mcp_url_realm_fails_closed(self) -> None:
        method = MockMethod()
        session = FakeClientSession([mcp_payment_error(realm="https://[malformed")])
        runtime = PaymentRuntime(
            [method],
            allowed_origins=["https://example.com"],
        )
        events: list[Any] = []
        runtime.events.on("*", events.append)
        try:
            with pytest.raises(ValueError, match="malformed.*disallowed"):
                await runtime.call_mcp_tool(session.call_tool, "premium_tool")
        finally:
            await runtime.aclose()

        assert len(session.calls) == 1
        method.create_credential.assert_not_called()
        assert events[-1].name == "payment.failed"
        assert events[-1].payload["credential"] is None

    @pytest.mark.asyncio
    async def test_shared_runtime_emits_mcp_payment_events(self) -> None:
        events: list[Any] = []
        runtime = PaymentRuntime([MockMethod()])
        runtime.events.on("*", events.append)
        session = FakeClientSession([mcp_payment_error(), FakeCallToolResult("paid")])

        await runtime.call_mcp_tool(session.call_tool, "premium_tool")

        assert [event.name for event in events] == [
            "challenge.received",
            "credential.created",
            "payment.response",
        ]
        assert all(event.payload["protocol"] == "mcp" for event in events)

    @pytest.mark.asyncio
    async def test_mcp_challenge_handler_can_supply_credential(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        credential = Credential(
            challenge=ChallengeEcho(
                id="event-id",
                realm="example.com",
                method="tempo",
                intent="charge",
                request="e30",
            ),
            payload={"hash": "0xevent"},
        )
        runtime.events.on("challenge.received", lambda _: credential)
        session = FakeClientSession([mcp_payment_error(), FakeCallToolResult("paid")])

        await runtime.call_mcp_tool(session.call_tool, "premium_tool")

        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_mcp_retry_failure_emits_payment_failed(self) -> None:
        events: list[Any] = []
        runtime = PaymentRuntime([MockMethod()])
        runtime.events.on("*", events.append)
        session = FakeClientSession([mcp_payment_error(), TimeoutError("timed out")])

        with pytest.raises(PaymentOutcomeUnknownError):
            await runtime.call_mcp_tool(session.call_tool, "premium_tool")

        assert events[-1].name == "payment.failed"
        assert isinstance(events[-1].payload["error"], PaymentOutcomeUnknownError)

    @pytest.mark.asyncio
    async def test_repeated_mcp_error_after_credential_never_pays_twice(self) -> None:
        method = MockMethod()
        session = FakeClientSession([mcp_payment_error(), mcp_payment_error()])
        runtime = PaymentRuntime([method])

        with pytest.raises(PaymentOutcomeUnknownError):
            await runtime.call_mcp_tool(session.call_tool, "premium_tool")

        assert len(session.calls) == 2
        assert method.create_credential.await_count == 1

    @pytest.mark.asyncio
    async def test_cancelled_mcp_retry_blocks_same_operation_from_paying_again(self) -> None:
        retry_started = asyncio.Event()
        events: list[Any] = []
        calls = 0
        method = MockMethod()
        runtime = PaymentRuntime([method])
        runtime.events.on("*", events.append)

        async def call_tool(*_args: Any, **_kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise mcp_payment_error()
            if calls == 2:
                retry_started.set()
                await asyncio.Event().wait()
            error = mcp_payment_error(realm="replacement.example")
            error.data["challenges"][0]["id"] = "replacement-id"
            raise error

        try:
            request = asyncio.create_task(
                runtime.call_mcp_tool(call_tool, "premium_tool", {"query": "same"})
            )
            await asyncio.wait_for(retry_started.wait(), 1)
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request

            with pytest.raises(PaymentOutcomeUnknownError):
                await runtime.call_mcp_tool(call_tool, "premium_tool", {"query": "same"})
        finally:
            await runtime.aclose()

        assert calls == 3
        assert method.create_credential.await_count == 1
        failures = [event for event in events if event.name == "payment.failed"]
        assert len(failures) == 2
        assert isinstance(failures[0].payload["error"].cause, asyncio.CancelledError)

    @pytest.mark.asyncio
    async def test_invalid_mcp_retry_metadata_does_not_lock_unsent_attempt(self) -> None:
        method = MockMethod()
        paid = FakeCallToolResult("paid")
        session = FakeClientSession([mcp_payment_error(), mcp_payment_error(), paid])
        runtime = PaymentRuntime([method])
        try:
            with pytest.raises(TypeError):
                await runtime.call_mcp_tool(
                    session.call_tool,
                    "premium_tool",
                    {"query": "same"},
                    meta=object(),
                )

            result = await runtime.call_mcp_tool(
                session.call_tool,
                "premium_tool",
                {"query": "same"},
            )
        finally:
            await runtime.aclose()

        assert result is paid
        assert len(session.calls) == 3
        assert method.create_credential.await_count == 2
