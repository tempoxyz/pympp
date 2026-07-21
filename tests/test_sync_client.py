"""Tests for synchronous payment-aware HTTP clients."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from mpp import Challenge
from mpp.agent import instrument
from mpp.client import SyncPaymentTransport
from mpp.errors import PaymentError
from mpp.runtime import PaymentRuntime, payment_flow_active
from tests import make_credential


class MockMethod:
    name = "tempo"
    _intents = {"charge": True}

    def __init__(self) -> None:
        self.loops: list[asyncio.AbstractEventLoop] = []
        self.create_credential = AsyncMock(side_effect=self._create_credential)

    async def _create_credential(self, challenge: Challenge):
        self.loops.append(asyncio.get_running_loop())
        return make_credential({"hash": "0xabc"}, challenge_id=challenge.id)


class MockTransport(httpx.BaseTransport):
    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []
        self.closed = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


class TrackingStream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.started = False
        self.closed = False

    def __iter__(self):
        self.started = True
        yield from self.chunks

    def close(self) -> None:
        self.closed = True


def challenge(**overrides: Any) -> Challenge:
    values = {"id": "test-id", "method": "tempo", "intent": "charge", "request": {}}
    values.update(overrides)
    return Challenge(**values)


def payment_required() -> httpx.Response:
    return httpx.Response(
        402,
        headers={"www-authenticate": challenge().to_www_authenticate("example.com")},
    )


class TestSyncPaymentTransport:
    def test_passes_through_free_response(self) -> None:
        inner = MockTransport([httpx.Response(200, content=b"ok")])
        transport = SyncPaymentTransport(methods=[], inner=inner)
        try:
            response = transport.handle_request(httpx.Request("GET", "https://example.com"))
        finally:
            transport.close()

        assert response.content == b"ok"
        assert len(inner.requests) == 1

    def test_replays_bytes_and_multipart_bodies(self) -> None:
        requests = [
            httpx.Request("POST", "https://example.com", content=b'{"hello":"world"}'),
            httpx.Request(
                "POST",
                "https://example.com",
                files={"file": ("hello.txt", b"hello", "text/plain")},
            ),
        ]

        for request in requests:
            inner = MockTransport([payment_required(), httpx.Response(200, content=b"paid")])
            transport = SyncPaymentTransport(methods=[MockMethod()], inner=inner)
            try:
                response = transport.handle_request(request)
            finally:
                transport.close()

            assert response.status_code == 200
            assert inner.requests[1].content == inner.requests[0].content
            assert inner.requests[1].headers["authorization"].startswith("Payment ")

    def test_rejects_generator_body_before_send(self) -> None:
        def body():
            yield b"one-shot"

        inner = MockTransport([])
        transport = SyncPaymentTransport(methods=[MockMethod()], inner=inner)
        try:
            with pytest.raises(PaymentError, match="Streaming request bodies"):
                transport.handle_request(
                    httpx.Request("POST", "https://example.com", content=body())
                )
        finally:
            transport.close()

        assert inner.requests == []

    def test_paid_stream_remains_lazy(self) -> None:
        stream = TrackingStream([b"one", b"two"])
        inner = MockTransport([payment_required(), httpx.Response(200, stream=stream)])
        transport = SyncPaymentTransport(methods=[MockMethod()], inner=inner)
        try:
            response = transport.handle_request(httpx.Request("GET", "https://example.com"))
            assert stream.started is False
            assert response.read() == b"onetwo"
            assert stream.started is True
        finally:
            transport.close()

    @pytest.mark.parametrize(
        ("www_authenticate", "expected_challenges"),
        [
            pytest.param("Payment invalid-base64!!", 0, id="malformed"),
            pytest.param(
                challenge(method="stripe").to_www_authenticate("example.com"),
                1,
                id="no-match",
            ),
            pytest.param(
                challenge(expires="2020-01-01T00:00:00Z").to_www_authenticate("example.com"),
                1,
                id="expired",
            ),
        ],
    )
    def test_nonpayable_challenges_fail_closed(
        self,
        www_authenticate: str,
        expected_challenges: int,
    ) -> None:
        method = MockMethod()
        inner = MockTransport([httpx.Response(402, headers={"www-authenticate": www_authenticate})])
        transport = SyncPaymentTransport(methods=[method], inner=inner)
        failed: list[dict[str, Any]] = []
        transport.on_payment_failed(failed.append)
        try:
            response = transport.handle_request(httpx.Request("GET", "https://example.com"))
        finally:
            transport.close()

        assert response.status_code == 402
        assert len(inner.requests) == 1
        method.create_credential.assert_not_called()
        assert len(failed) == 1
        assert len(failed[0]["challenges"]) == expected_challenges
        assert failed[0]["credential"] is None
        assert failed[0]["response"] is response

    @pytest.mark.parametrize("failure_stage", ["credential", "retry"])
    def test_payment_failures_emit_and_propagate(self, failure_stage: str) -> None:
        error = RuntimeError(f"{failure_stage} failed")
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if len(requests) == 1:
                return payment_required()
            raise error

        method = MockMethod()
        if failure_stage == "credential":
            method.create_credential.side_effect = error
        transport = SyncPaymentTransport(
            methods=[method],
            inner=httpx.MockTransport(handler),
        )
        failed: list[dict[str, Any]] = []
        transport.on_payment_failed(failed.append)
        try:
            with pytest.raises(RuntimeError, match=f"{failure_stage} failed") as raised:
                transport.handle_request(httpx.Request("GET", "https://example.com"))
        finally:
            transport.close()

        assert raised.value is error
        assert len(requests) == (1 if failure_stage == "credential" else 2)
        assert len(failed) == 1
        assert failed[0]["challenge"].id == "test-id"
        if failure_stage == "credential":
            assert failed[0]["credential"] is None
        else:
            assert failed[0]["credential"] is not None
        assert failed[0]["error"] is error

    def test_lifecycle_handler_can_supply_sync_credential(self) -> None:
        method = MockMethod()
        credential = make_credential({"hash": "0xevent"}, challenge_id="test-id")
        inner = MockTransport([payment_required(), httpx.Response(200, content=b"paid")])
        transport = SyncPaymentTransport(methods=[method], inner=inner)
        events: list[str] = []
        transport.on_challenge_received(lambda _payload: credential)
        transport.on_credential_created(lambda payload: events.append("credential"))
        transport.on_payment_response(lambda payload: events.append("response"))
        try:
            response = transport.handle_request(httpx.Request("GET", "https://example.com"))
        finally:
            transport.close()

        assert response.status_code == 200
        assert events == ["credential", "response"]
        assert inner.requests[1].headers["authorization"] == credential.to_authorization()
        method.create_credential.assert_not_called()

    def test_close_preserves_borrowed_runtime(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        inner = MockTransport([])
        transport = SyncPaymentTransport(inner=inner, runtime=runtime)
        try:
            runtime.create_credential_sync(challenge(), method)
            transport.close()
            runtime.create_credential_sync(challenge(), method)
        finally:
            transport.close()
            runtime.close()

        assert inner.closed

    def test_sync_response_hook_runs_for_credentialed_402(self) -> None:
        contexts: list[object | None] = []

        class HookMethod:
            name = "tempo"
            _intents = {"charge": True}

            async def create_credential(
                self,
                challenge: Challenge,
                *,
                context: object | None = None,
            ):
                contexts.append(context)
                return make_credential({"context": context}, challenge_id=challenge.id)

            def handle_http_response(self, exchange):
                exchange.create_credential({"action": "voucher"})
                exchange.response.close()
                return httpx.Response(200, content=b"handled")

        paid_response = httpx.Response(402)
        inner = MockTransport([payment_required(), paid_response])
        transport = SyncPaymentTransport(methods=[HookMethod()], inner=inner)
        try:
            response = transport.handle_request(httpx.Request("GET", "https://example.com/paid"))
        finally:
            transport.close()

        assert response.content == b"handled"
        assert response.request.url == httpx.URL("https://example.com/paid")
        assert contexts == [None, {"action": "voucher"}]
        assert paid_response.is_closed

    def test_sync_response_hook_can_run_async_and_refetch_once(self) -> None:
        hook_calls = 0

        class HookMethod(MockMethod):
            def handle_http_response(self, exchange):
                nonlocal hook_calls
                hook_calls += 1
                assert payment_flow_active()
                assert exchange.run_sync(asyncio.sleep(0, result="ok")) == "ok"
                if hook_calls == 2:
                    assert exchange.refetch is None
                    return exchange.response
                assert exchange.refetch is not None
                return exchange.refetch()

        inner = MockTransport(
            [
                payment_required(),
                httpx.Response(204),
                payment_required(),
                httpx.Response(200, content=b"stream"),
            ]
        )
        transport = SyncPaymentTransport(methods=[HookMethod()], inner=inner)
        events: list[tuple[int, bool]] = []
        transport.on_payment_response(
            lambda payload: events.append((payload["response"].status_code, payment_flow_active()))
        )
        try:
            response = transport.handle_request(httpx.Request("GET", "https://example.com/paid"))
        finally:
            transport.close()

        assert response.content == b"stream"
        assert response.request.url == httpx.URL("https://example.com/paid")
        assert events == [(204, True), (200, True)]
        assert len(inner.requests) == 4

    def test_replacement_response_can_own_paid_stream(self) -> None:
        class HookMethod(MockMethod):
            def handle_http_response(self, exchange):
                return httpx.Response(
                    exchange.response.status_code,
                    headers=exchange.response.headers,
                    stream=exchange.response.stream,
                )

        stream = TrackingStream([b"one", b"two"])
        inner = MockTransport([payment_required(), httpx.Response(200, stream=stream)])
        transport = SyncPaymentTransport(methods=[HookMethod()], inner=inner)
        try:
            response = transport.handle_request(httpx.Request("GET", "https://example.com/paid"))
            assert stream.started is False
            assert response.read() == b"onetwo"
            response.close()
        finally:
            transport.close()

        assert stream.closed


class TestWrappedSyncClient:
    def test_wrap_client_is_idempotent_and_preserves_payment_authorization(self) -> None:
        inner = MockTransport([payment_required(), httpx.Response(200, content=b"paid")])
        runtime = PaymentRuntime([MockMethod()])
        client = httpx.Client(transport=inner, auth=("user", "password"))
        try:
            assert runtime.wrap_client(client) is client
            assert runtime.wrap_client(client) is client
            response = client.get("https://example.com/paid")
        finally:
            client.close()
            runtime.close()

        assert response.status_code == 200
        assert inner.requests[0].headers["authorization"].startswith("Basic ")
        assert inner.requests[1].headers["authorization"].startswith("Payment ")

    def test_redirected_402_uses_challenged_origin_policy(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.host == "allowed.example":
                return httpx.Response(302, headers={"location": "https://evil.example/paid"})
            return payment_required()

        method = MockMethod()
        runtime = PaymentRuntime([method], allowed_origins=["https://allowed.example"])
        client = runtime.wrap_client(
            httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
        )
        try:
            response = client.get("https://allowed.example/start")
        finally:
            client.close()
            runtime.close()

        assert response.status_code == 402
        assert [request.url.host for request in requests] == ["allowed.example", "evil.example"]
        method.create_credential.assert_not_called()


class TestRuntimeBridge:
    def test_concurrent_sync_calls_share_one_method_loop(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(
                    pool.map(
                        lambda _: runtime.create_credential_sync(challenge(), method),
                        range(4),
                    )
                )
        finally:
            runtime.close()

        assert len(method.loops) == 4
        assert len({id(loop) for loop in method.loops}) == 1

    @pytest.mark.asyncio
    async def test_async_method_stays_on_caller_loop(self) -> None:
        caller_loop = asyncio.get_running_loop()
        future = caller_loop.create_future()
        method = MockMethod()

        async def create(challenge: Challenge):
            await future
            return make_credential({"hash": "0xabc"}, challenge_id=challenge.id)

        method.create_credential = AsyncMock(side_effect=create)
        runtime = PaymentRuntime([method])
        try:
            task = asyncio.create_task(runtime.create_credential(challenge(), method))
            await asyncio.sleep(0)
            future.set_result(None)
            await task
        finally:
            runtime.close()

    def test_bridge_rejects_same_thread_blocking(self) -> None:
        runtime = PaymentRuntime([])

        async def block_bridge() -> None:
            with pytest.raises(RuntimeError, match="Cannot block"):
                runtime._bridge.run(asyncio.sleep(0))

        try:
            runtime._bridge.run(block_bridge())
        finally:
            runtime.close()

    def test_close_cancels_in_flight_bridge_work(self) -> None:
        started = threading.Event()

        class BlockingMethod(MockMethod):
            async def _create_credential(self, challenge: Challenge) -> Any:
                started.set()
                await asyncio.Event().wait()

        method = BlockingMethod()
        runtime = PaymentRuntime([method])
        errors: list[BaseException] = []

        def create() -> None:
            try:
                runtime.create_credential_sync(challenge(), method)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=create)
        thread.start()
        assert started.wait(1)
        runtime.close()
        thread.join(timeout=1)

        assert thread.is_alive() is False
        assert errors

    def test_close_is_idempotent(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        runtime.create_credential_sync(challenge(), method)

        runtime.close()
        runtime.close()

        with pytest.raises(RuntimeError, match="closed"):
            runtime.create_credential_sync(challenge(), method)


def test_instrumented_openai_sync_streaming_in_worker_thread() -> None:
    openai = pytest.importorskip("openai")
    requests: list[httpx.Request] = []
    bodies: list[bytes] = []
    paid_stream = TrackingStream(
        [
            b'data: {"id":"chatcmpl-test","object":"chat.completion.chunk",'
            b'"created":0,"model":"test","choices":[{"index":0,"delta":'
            b'{"content":"hel"},"finish_reason":null}]}\n\n',
            b'data: {"id":"chatcmpl-test","object":"chat.completion.chunk",'
            b'"created":0,"model":"test","choices":[{"index":0,"delta":'
            b'{"content":"lo"},"finish_reason":"stop"}]}\n\n',
            b"data: [DONE]\n\n",
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        bodies.append(request.content)
        if len(requests) == 1:
            return payment_required()
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=paid_stream,
        )

    runtime = PaymentRuntime([MockMethod()])
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = openai.OpenAI(
        api_key="test",
        base_url="https://example.com/v1",
        http_client=http_client,
        max_retries=0,
    )
    handle = instrument(runtime, mcp=False)
    result: dict[str, Any] = {}

    def run() -> None:
        try:
            stream = client.chat.completions.create(
                model="test",
                messages=[{"role": "user", "content": "hello"}],
                stream=True,
            )
            result["lazy"] = not paid_stream.started
            result["text"] = "".join(chunk.choices[0].delta.content or "" for chunk in stream)
        except BaseException as error:
            result["error"] = error

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(timeout=5)
    try:
        assert thread.is_alive() is False
        if error := result.get("error"):
            raise error
        assert result == {"lazy": True, "text": "hello"}
        assert len(requests) == 2
        assert bodies[0] == bodies[1]
        assert requests[1].headers["authorization"].startswith("Payment ")
    finally:
        handle.disable()
        client.close()
        runtime.close()
