"""Tests for synchronous payment-aware HTTP clients."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.client import SyncPaymentTransport
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
from mpp.instrumentation import instrument
from mpp.runtime import PaymentRuntime
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


class ConsumingTransport(httpx.BaseTransport):
    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []
        self.bodies: list[bytes] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        stream = cast(httpx.SyncByteStream, request.stream)
        self.bodies.append(b"".join(stream))
        return self.responses.pop(0)


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


class BrokenTrackingStream(TrackingStream):
    def __iter__(self):
        self.started = True
        raise httpx.ReadError("body lost")
        yield b""  # pragma: no cover


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
            inner = ConsumingTransport([payment_required(), httpx.Response(200, content=b"paid")])
            transport = SyncPaymentTransport(methods=[MockMethod()], inner=inner)
            try:
                response = transport.handle_request(request)
            finally:
                transport.close()

            assert response.status_code == 200
            assert inner.bodies[1] == inner.bodies[0]
            assert inner.requests[1].headers["authorization"].startswith("Payment ")

    def test_free_generator_body_passes_through(self) -> None:
        def body():
            yield b"one-shot"

        received: list[bytes] = []

        def handler(request: httpx.Request) -> httpx.Response:
            stream = cast(httpx.SyncByteStream, request.stream)
            received.append(b"".join(stream))
            return httpx.Response(200, content=b"ok")

        inner = httpx.MockTransport(handler)
        transport = SyncPaymentTransport(methods=[MockMethod()], inner=inner)
        try:
            response = transport.handle_request(
                httpx.Request("POST", "https://example.com", content=body())
            )
        finally:
            transport.close()

        assert response.status_code == 200
        assert received == [b"one-shot"]

    def test_paid_generator_body_fails_after_first_send(self) -> None:
        def body():
            yield b"one-shot"

        requests: list[httpx.Request] = []
        response_stream = TrackingStream([b"payment explanation"])

        class OneShotTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                requests.append(request)
                stream = cast(httpx.SyncByteStream, request.stream)
                _ = b"".join(stream)
                return httpx.Response(
                    402,
                    headers={"www-authenticate": challenge().to_www_authenticate("example.com")},
                    stream=response_stream,
                )

        transport = SyncPaymentTransport(
            methods=[MockMethod()],
            inner=OneShotTransport(),
        )
        try:
            with pytest.raises(PaymentError, match="cannot be replayed"):
                transport.handle_request(
                    httpx.Request("POST", "https://example.com", content=body())
                )
        finally:
            transport.close()

        assert len(requests) == 1
        assert response_stream.closed is True

    def test_paid_stream_remains_lazy(self) -> None:
        stream = TrackingStream([b"one", b"two"])
        inner = MockTransport([payment_required(), httpx.Response(200, stream=stream)])
        transport = SyncPaymentTransport(methods=[MockMethod()], inner=inner)
        try:
            response = transport.handle_request(httpx.Request("GET", "https://example.com"))
            outcome_stream = cast(Any, response.stream)
            assert outcome_stream._runtime is not None
            assert outcome_stream._attempt is not None
            assert stream.started is False
            assert response.read() == b"onetwo"
            assert stream.started is True
            assert outcome_stream._runtime is None
            assert outcome_stream._attempt is None
        finally:
            transport.close()

    @pytest.mark.parametrize("terminal", ["error", "close"])
    def test_paid_stream_releases_attempt_on_noncomplete_terminal(
        self,
        terminal: str,
    ) -> None:
        stream: TrackingStream = (
            BrokenTrackingStream([]) if terminal == "error" else TrackingStream([b"paid"])
        )
        transport = SyncPaymentTransport(
            methods=[MockMethod()],
            inner=MockTransport(
                [
                    payment_required(),
                    httpx.Response(200, stream=stream),
                ]
            ),
        )
        response = transport.handle_request(httpx.Request("GET", "https://example.com"))
        outcome_stream = cast(Any, response.stream)
        assert outcome_stream._runtime is not None
        assert outcome_stream._attempt is not None
        try:
            if terminal == "error":
                with pytest.raises(httpx.ReadError, match="body lost"):
                    response.read()
            else:
                response.close()
            assert outcome_stream._runtime is None
            assert outcome_stream._attempt is None
        finally:
            response.close()
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
        assert failed[0]["protocol"] == "http"
        assert failed[0]["response"] is response

    @pytest.mark.parametrize(
        "www_authenticate",
        [
            pytest.param("Bearer realm=test", id="non-payment"),
            pytest.param("Payment invalid-base64!!", id="malformed"),
            pytest.param(
                challenge(method="stripe").to_www_authenticate("example.com"),
                id="unsupported",
            ),
            pytest.param(
                challenge(expires="2020-01-01T00:00:00Z").to_www_authenticate("example.com"),
                id="expired",
            ),
        ],
    )
    def test_nonpayable_402_body_remains_lazy(self, www_authenticate: str) -> None:
        stream = TrackingStream([b"explanation"])
        response = httpx.Response(
            402,
            headers={"www-authenticate": www_authenticate},
            stream=stream,
        )
        transport = SyncPaymentTransport(
            methods=[MockMethod()],
            inner=MockTransport([response]),
        )
        try:
            returned = transport.handle_request(httpx.Request("GET", "https://example.com"))
            assert returned is response
            assert stream.started is False
            assert stream.closed is False
            assert returned.read() == b"explanation"
            assert stream.started is True
            assert stream.closed is True
        finally:
            transport.close()

    def test_disallowed_402_body_remains_lazy(self) -> None:
        stream = TrackingStream([b"explanation"])
        response = httpx.Response(
            402,
            headers={"www-authenticate": challenge().to_www_authenticate("example.com")},
            stream=stream,
        )
        runtime = PaymentRuntime(
            [MockMethod()],
            allowed_origins=["https://allowed.example"],
        )
        transport = SyncPaymentTransport(
            runtime=runtime,
            inner=MockTransport([response]),
        )
        try:
            returned = transport.handle_request(httpx.Request("GET", "https://disallowed.example"))
            assert returned is response
            assert stream.started is False
            assert stream.closed is False
        finally:
            response.close()
            transport.close()
            runtime.close()

    def test_handles_comma_combined_authentication_challenges(self) -> None:
        payment = challenge(
            request={"description": "one,two"},
            description='quoted, comma and \\"escape',
        ).to_www_authenticate("example.com")
        method = MockMethod()
        transport = SyncPaymentTransport(
            methods=[method],
            inner=MockTransport(
                [
                    httpx.Response(
                        402,
                        headers={
                            "www-authenticate": (
                                'Bearer realm="legacy", error="expired", '
                                f'{payment}, Basic realm="fallback"'
                            )
                        },
                    ),
                    httpx.Response(200, content=b"paid"),
                ]
            ),
        )
        try:
            response = transport.handle_request(httpx.Request("GET", "https://example.com"))
        finally:
            transport.close()

        assert response.status_code == 200
        method.create_credential.assert_awaited_once()

    def test_initial_payment_failed_event_abort_closes_response(self) -> None:
        class EventAbort(BaseException):
            pass

        def abort(_payload: Any) -> None:
            raise EventAbort

        stream = TrackingStream([b"payment explanation"])
        response = httpx.Response(
            402,
            headers={
                "www-authenticate": challenge(method="stripe").to_www_authenticate("example.com")
            },
            stream=stream,
        )
        transport = SyncPaymentTransport(
            methods=[MockMethod()],
            inner=MockTransport([response]),
        )
        transport.on_payment_failed(abort)
        try:
            with pytest.raises(EventAbort):
                transport.handle_request(httpx.Request("GET", "https://example.com"))
        finally:
            transport.close()

        assert stream.closed is True

    @pytest.mark.parametrize("failure_stage", ["credential", "serialization", "retry"])
    def test_payment_failures_emit_and_propagate(
        self,
        failure_stage: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        error = RuntimeError(f"{failure_stage} failed")
        requests: list[httpx.Request] = []

        def fail_serialization(_credential: Credential) -> str:
            raise error

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if len(requests) == 1:
                return payment_required()
            raise error

        method = MockMethod()
        if failure_stage == "credential":
            method.create_credential.side_effect = error
        elif failure_stage == "serialization":
            monkeypatch.setattr(Credential, "to_authorization", fail_serialization)
        transport = SyncPaymentTransport(
            methods=[method],
            inner=httpx.MockTransport(handler),
        )
        failed: list[dict[str, Any]] = []
        transport.on_payment_failed(failed.append)
        try:
            expected_error = (
                PaymentOutcomeUnknownError if failure_stage == "retry" else RuntimeError
            )
            with pytest.raises(expected_error) as raised:
                transport.handle_request(httpx.Request("GET", "https://example.com"))
        finally:
            transport.close()

        if failure_stage == "retry":
            assert raised.value.__cause__ is error
        else:
            assert raised.value is error
        assert len(requests) == (2 if failure_stage == "retry" else 1)
        assert len(failed) == 1
        assert failed[0]["challenge"].id == "test-id"
        if failure_stage in {"credential", "serialization"}:
            assert failed[0]["credential"] is None
        else:
            assert failed[0]["credential"] is not None
        assert isinstance(failed[0]["error"], expected_error)

    def test_repeated_402_after_credential_has_unknown_outcome(self) -> None:
        method = MockMethod()
        inner = MockTransport([payment_required(), payment_required()])
        transport = SyncPaymentTransport(methods=[method], inner=inner)
        try:
            with pytest.raises(PaymentOutcomeUnknownError, match="Do not blindly retry"):
                transport.handle_request(httpx.Request("GET", "https://example.com"))
        finally:
            transport.close()

        assert len(inner.requests) == 2
        method.create_credential.assert_awaited_once()

    @pytest.mark.parametrize("status_code", [200, 402, 503])
    def test_event_abort_closes_unreturned_paid_response(
        self,
        status_code: int,
    ) -> None:
        class EventAbort(BaseException):
            pass

        def abort(_payload: Any) -> None:
            raise EventAbort

        stream = TrackingStream([b"paid response"])
        transport = SyncPaymentTransport(
            methods=[MockMethod()],
            inner=MockTransport(
                [
                    payment_required(),
                    httpx.Response(status_code, stream=stream),
                ]
            ),
        )
        if status_code == 200:
            transport.on_payment_response(abort)
        else:
            transport.on_payment_failed(abort)
        try:
            with pytest.raises(EventAbort):
                transport.handle_request(httpx.Request("GET", "https://example.com"))
        finally:
            transport.close()

        assert stream.closed is True

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

    def test_free_generator_upload_is_not_buffered(self) -> None:
        bodies: list[bytes] = []

        def handler(request: httpx.Request) -> httpx.Response:
            bodies.append(request.read())
            return httpx.Response(200, content=b"ok")

        def body():
            yield b"one-"
            yield b"shot"

        runtime = PaymentRuntime([MockMethod()])
        client = runtime.wrap_client(httpx.Client(transport=httpx.MockTransport(handler)))
        try:
            response = client.post("https://example.com/upload", content=body())
        finally:
            client.close()
            runtime.close()

        assert response.status_code == 200
        assert bodies == [b"one-shot"]


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
    async def test_sync_and_async_methods_share_runtime_loop(self) -> None:
        caller_loop = asyncio.get_running_loop()
        method = MockMethod()
        runtime = PaymentRuntime([method])
        event_loops: list[asyncio.AbstractEventLoop] = []
        runtime.events.on("*", lambda _: event_loops.append(asyncio.get_running_loop()))
        try:
            await runtime.create_credential(challenge(), method)
            await asyncio.to_thread(runtime.create_credential_sync, challenge(), method)
        finally:
            runtime.close()

        assert len(method.loops) == 2
        assert method.loops[0] is method.loops[1]
        assert method.loops[0] is not caller_loop
        assert len(event_loops) == 4
        assert set(event_loops) == {method.loops[0]}

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

    def test_close_waits_for_committed_http_retry(self) -> None:
        retry_started = threading.Event()
        retry_release = threading.Event()
        calls = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return payment_required()
            retry_started.set()
            assert retry_release.wait(1)
            return httpx.Response(200, content=b"paid")

        runtime = PaymentRuntime([MockMethod()])
        transport = SyncPaymentTransport(runtime=runtime, inner=httpx.MockTransport(handler))
        responses: list[httpx.Response] = []
        errors: list[BaseException] = []
        closed = threading.Event()

        def request() -> None:
            try:
                responses.append(
                    transport.handle_request(httpx.Request("GET", "https://example.com"))
                )
            except BaseException as error:
                errors.append(error)

        request_thread = threading.Thread(target=request)
        close_thread = threading.Thread(target=lambda: (runtime.close(), closed.set()))
        request_thread.start()
        assert retry_started.wait(1)
        close_thread.start()
        assert not closed.wait(0.05)

        retry_release.set()
        for thread in (request_thread, close_thread):
            thread.join(timeout=1)
            assert not thread.is_alive()
        transport.close()

        assert not errors
        assert responses[0].status_code == 200
        assert closed.is_set()

    def test_concurrent_close_waits_for_shutdown_completion(self) -> None:
        started = threading.Event()
        cleanup_started = threading.Event()
        cleanup_release = threading.Event()

        class BlockingMethod(MockMethod):
            async def _create_credential(self, challenge: Challenge) -> Any:
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cleanup_started.set()
                    while not cleanup_release.is_set():
                        await asyncio.sleep(0.01)

        runtime = PaymentRuntime([BlockingMethod()])

        def create() -> None:
            try:
                runtime.create_credential_sync(challenge(), runtime.methods[0])
            except BaseException:
                pass

        create_thread = threading.Thread(target=create)
        first_close = threading.Thread(target=runtime.close)
        second_returned = threading.Event()
        second_close = threading.Thread(target=lambda: (runtime.close(), second_returned.set()))
        create_thread.start()
        assert started.wait(1)
        first_close.start()
        assert cleanup_started.wait(1)
        second_close.start()
        assert not second_returned.wait(0.05)

        cleanup_release.set()
        for thread in (create_thread, first_close, second_close):
            thread.join(timeout=1)
            assert not thread.is_alive()
        assert second_returned.is_set()


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

    runtime = PaymentRuntime(
        [MockMethod()],
        allowed_origins=["https://example.com"],
    )
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = openai.OpenAI(
        api_key="test",
        base_url="https://example.com/v1",
        http_client=http_client,
        max_retries=0,
    )
    handle = instrument(runtime, scope="process")
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
