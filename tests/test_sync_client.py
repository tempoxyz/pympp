"""Tests for synchronous payment-aware HTTP clients."""

from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.client import SyncPaymentTransport
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
from mpp.runtime import OwnedPaymentRuntime, PaymentRuntime
from tests import make_credential


class MockMethod:
    name = "tempo"
    _intents = {"charge": True}

    def __init__(self) -> None:
        self.loops: list[asyncio.AbstractEventLoop] = []
        self.create_credential = AsyncMock(side_effect=self._create_credential)

    async def _create_credential(self, challenge: Challenge) -> Credential:
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


class ConsumingTransport(MockTransport):
    def __init__(self, responses: list[httpx.Response]) -> None:
        super().__init__(responses)
        self.bodies: list[bytes] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.bodies.append(b"".join(cast(httpx.SyncByteStream, request.stream)))
        return self.responses.pop(0)


class TrackingStream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes], *, broken: bool = False) -> None:
        self.chunks = chunks
        self.broken = broken
        self.started = False
        self.closed = False

    def __iter__(self):
        self.started = True
        if self.broken:
            raise httpx.ReadError("body lost")
        yield from self.chunks

    def close(self) -> None:
        self.closed = True


class NonSeekableFile:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.content)
        chunk, self.content = self.content[:size], self.content[size:]
        return chunk


def challenge(**overrides: Any) -> Challenge:
    values = {"id": "test-id", "method": "tempo", "intent": "charge", "request": {}}
    values.update(overrides)
    return Challenge(**values)


def payment_required(**overrides: Any) -> httpx.Response:
    return httpx.Response(
        402,
        headers={"www-authenticate": challenge(**overrides).to_www_authenticate("example.com")},
    )


def test_passes_through_free_response_without_starting_runtime() -> None:
    inner = MockTransport([httpx.Response(200, content=b"ok")])
    transport = SyncPaymentTransport(methods=[], inner=inner)
    runtime = transport._runtime

    response = transport.handle_request(httpx.Request("GET", "https://example.com"))
    transport.close()

    assert response.content == b"ok"
    assert len(inner.requests) == 1
    with pytest.raises(RuntimeError, match="closed"):
        runtime.start()


def test_paid_retry_applies_and_propagates_challenge_cookies() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if "authorization" not in request.headers:
            return httpx.Response(
                402,
                headers=[
                    ("www-authenticate", challenge().to_www_authenticate("example.com")),
                    ("set-cookie", "session=new; Path=/"),
                    ("set-cookie", "payment_nonce=nonce-1; Path=/"),
                ],
            )
        return httpx.Response(
            200,
            headers={"set-cookie": "final_cookie=ok; Path=/"},
            content=b"paid",
        )

    transport = SyncPaymentTransport(methods=[MockMethod()], inner=httpx.MockTransport(handler))
    with httpx.Client(transport=transport) as client:
        client.cookies.set("session", "old", domain="example.com", path="/")
        response = client.get("https://example.com/paid")

    retry_cookies = SimpleCookie(requests[1].headers["cookie"])
    assert response.status_code == 200
    assert retry_cookies["session"].value == "new"
    assert retry_cookies["payment_nonce"].value == "nonce-1"
    assert dict(client.cookies) == {
        "session": "new",
        "payment_nonce": "nonce-1",
        "final_cookie": "ok",
    }
    assert response.headers.get_list("set-cookie") == [
        "session=new; Path=/",
        "payment_nonce=nonce-1; Path=/",
        "final_cookie=ok; Path=/",
    ]


@pytest.mark.parametrize(
    "request_value",
    [
        pytest.param(
            httpx.Request("POST", "https://example.com", content=b'{"hello":"world"}'),
            id="bytes",
        ),
        pytest.param(
            httpx.Request(
                "POST",
                "https://example.com",
                files={"file": ("hello.txt", b"hello", "text/plain")},
            ),
            id="multipart",
        ),
    ],
)
def test_replays_buffered_request_bodies(request_value: httpx.Request) -> None:
    inner = ConsumingTransport([payment_required(), httpx.Response(200, content=b"paid")])
    transport = SyncPaymentTransport(methods=[MockMethod()], inner=inner)
    try:
        response = transport.handle_request(request_value)
    finally:
        transport.close()

    assert response.status_code == 200
    assert inner.bodies[1] == inner.bodies[0]
    assert inner.requests[1].headers["authorization"].startswith("Payment ")


def test_replays_non_seekable_multipart_file() -> None:
    inner = ConsumingTransport([payment_required(), httpx.Response(200, content=b"paid")])
    transport = SyncPaymentTransport(methods=[MockMethod()], inner=inner)
    request = httpx.Request(
        "POST",
        "https://example.com",
        files={
            "file": (
                "hello.txt",
                cast(Any, NonSeekableFile(b"FILE-CONTENT")),
                "text/plain",
            )
        },
    )
    try:
        response = transport.handle_request(request)
    finally:
        transport.close()

    assert response.status_code == 200
    assert inner.bodies[0] == inner.bodies[1]
    assert b"FILE-CONTENT" in inner.bodies[1]


def test_free_generator_body_passes_through() -> None:
    received: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(b"".join(cast(httpx.SyncByteStream, request.stream)))
        return httpx.Response(200, content=b"ok")

    transport = SyncPaymentTransport(methods=[MockMethod()], inner=httpx.MockTransport(handler))
    try:
        response = transport.handle_request(
            httpx.Request("POST", "https://example.com", content=iter([b"one-shot"]))
        )
    finally:
        transport.close()

    assert response.status_code == 200
    assert received == [b"one-shot"]


def test_paid_generator_body_fails_and_closes_challenge_response() -> None:
    response_stream = TrackingStream([b"payment explanation"])

    def body():
        yield b"one-shot"

    class OneShotTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            _ = b"".join(cast(httpx.SyncByteStream, request.stream))
            return httpx.Response(
                402,
                headers={"www-authenticate": challenge().to_www_authenticate("example.com")},
                stream=response_stream,
            )

    transport = SyncPaymentTransport(methods=[MockMethod()], inner=OneShotTransport())
    try:
        with pytest.raises(PaymentError, match="cannot be replayed"):
            transport.handle_request(httpx.Request("POST", "https://example.com", content=body()))
    finally:
        transport.close()

    assert response_stream.closed


@pytest.mark.parametrize("terminal", ["complete", "error", "close"])
def test_success_status_completes_payment_before_body(terminal: str) -> None:
    stream = TrackingStream([b"paid"], broken=terminal == "error")
    method = MockMethod()
    runtime = OwnedPaymentRuntime([method])
    transport = SyncPaymentTransport(
        runtime=runtime,
        inner=MockTransport(
            [
                payment_required(),
                httpx.Response(200, stream=stream),
                payment_required(),
                httpx.Response(200, content=b"again"),
            ]
        ),
    )
    response = transport.handle_request(httpx.Request("GET", "https://example.com"))

    assert not stream.started
    try:
        if terminal == "complete":
            assert response.read() == b"paid"
        elif terminal == "error":
            with pytest.raises(httpx.ReadError, match="body lost"):
                response.read()
        else:
            response.close()
        again = transport.handle_request(httpx.Request("GET", "https://example.com"))
        assert again.content == b"again"
        assert method.create_credential.await_count == 2
    finally:
        response.close()
        transport.close()
        runtime.close()


def test_redirect_cannot_trigger_a_second_payment() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "start.test":
            if "authorization" not in request.headers:
                return payment_required(id="first")
            return httpx.Response(302, headers={"location": "https://next.test/resource"})
        return payment_required(id="second")

    method = MockMethod()
    transport = SyncPaymentTransport(methods=[method], inner=httpx.MockTransport(handler))
    with httpx.Client(transport=transport, follow_redirects=True) as client:
        response = client.get("https://start.test/resource")

    assert response.status_code == 402
    assert [request.url.host for request in requests] == ["start.test", "start.test", "next.test"]
    assert "authorization" not in requests[-1].headers
    method.create_credential.assert_awaited_once()


@pytest.mark.parametrize(
    ("header", "failed_events"),
    [
        pytest.param("Bearer realm=test", 0, id="non-payment"),
        pytest.param("Payment invalid-base64!!", 1, id="malformed"),
        pytest.param(
            challenge(method="stripe").to_www_authenticate("example.com"),
            1,
            id="unsupported",
        ),
        pytest.param(
            challenge(expires="2020-01-01T00:00:00Z").to_www_authenticate("example.com"),
            1,
            id="expired",
        ),
    ],
)
def test_nonpayable_402_remains_lazy(header: str, failed_events: int) -> None:
    stream = TrackingStream([b"explanation"])
    response = httpx.Response(402, headers={"www-authenticate": header}, stream=stream)
    transport = SyncPaymentTransport(
        methods=[MockMethod()],
        inner=MockTransport([response]),
    )
    failed: list[dict[str, Any]] = []
    transport.on_payment_failed(failed.append)
    try:
        returned = transport.handle_request(httpx.Request("GET", "https://example.com"))
        assert returned is response
        assert not stream.started and not stream.closed
        if header.startswith("Bearer "):
            assert transport._runtime._state == "new"
        assert returned.read() == b"explanation"
    finally:
        transport.close()

    assert len(failed) == failed_events


def test_disallowed_402_remains_lazy() -> None:
    stream = TrackingStream([b"explanation"])
    response = httpx.Response(
        402,
        headers={"www-authenticate": challenge().to_www_authenticate("example.com")},
        stream=stream,
    )
    runtime = OwnedPaymentRuntime(
        [MockMethod()],
        allowed_origins=["https://allowed.example"],
    )
    transport = SyncPaymentTransport(runtime=runtime, inner=MockTransport([response]))
    try:
        returned = transport.handle_request(httpx.Request("GET", "https://disallowed.example"))
        assert returned is response
        assert not stream.started and not stream.closed
        assert runtime._state == "new"
    finally:
        response.close()
        transport.close()
        runtime.close()


def test_runtime_start_failure_closes_challenge_response() -> None:
    stream = TrackingStream([b"payment explanation"])

    @asynccontextmanager
    async def failed_factory():
        raise RuntimeError("factory failed")
        yield MockMethod()  # pragma: no cover

    response = httpx.Response(
        402,
        headers={
            "www-authenticate": challenge().to_www_authenticate("example.com"),
        },
        stream=stream,
    )
    runtime = OwnedPaymentRuntime(method_factories=[failed_factory])
    transport = SyncPaymentTransport(runtime=runtime, inner=MockTransport([response]))
    try:
        with pytest.raises(RuntimeError, match="factory failed"):
            transport.handle_request(httpx.Request("GET", "https://example.com"))
    finally:
        transport.close()
        runtime.close()

    assert stream.closed


@pytest.mark.parametrize("stage", ["credential", "serialization", "retry"])
def test_payment_failures_emit_and_propagate(
    stage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = RuntimeError(f"{stage} failed")
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return payment_required()
        raise error

    method = MockMethod()
    if stage == "credential":
        method.create_credential.side_effect = error
    elif stage == "serialization":
        monkeypatch.setattr(
            Credential, "to_authorization", lambda _self: (_ for _ in ()).throw(error)
        )

    transport = SyncPaymentTransport(methods=[method], inner=httpx.MockTransport(handler))
    failed: list[dict[str, Any]] = []
    transport.on_payment_failed(failed.append)
    try:
        expected = PaymentOutcomeUnknownError if stage == "retry" else RuntimeError
        with pytest.raises(expected):
            transport.handle_request(httpx.Request("GET", "https://example.com"))
    finally:
        transport.close()

    assert len(failed) == 1
    assert isinstance(failed[0]["error"], expected)
    if stage == "retry":
        assert failed[0]["credential"] is not None
    else:
        assert failed[0]["credential"] is None


def test_repeated_402_after_credential_is_unknown() -> None:
    method = MockMethod()
    transport = SyncPaymentTransport(
        methods=[method],
        inner=MockTransport([payment_required(), payment_required()]),
    )
    try:
        with pytest.raises(PaymentOutcomeUnknownError, match="Do not blindly retry"):
            transport.handle_request(httpx.Request("GET", "https://example.com"))
    finally:
        transport.close()

    method.create_credential.assert_awaited_once()


def test_send_boundary_failure_reports_retained_credential() -> None:
    method = MockMethod()
    runtime = OwnedPaymentRuntime([method])
    retained = make_credential({"hash": "0xretained"}, challenge_id="blocker")
    request = httpx.Request(
        "POST",
        "https://example.com",
        content=b"same operation",
    )

    def retain_unknown(_payload: dict[str, Any]) -> None:
        blocker_request = httpx.Request(
            "POST",
            request.url,
            content=b"same operation",
        )
        blocker = runtime._begin_http_payment(
            challenge(id="blocker"),
            blocker_request,
        )
        blocker.credential = retained
        blocker.mark_sent(blocker_request)
        blocker.unknown(TimeoutError("response lost"))

    failed: list[dict[str, Any]] = []
    runtime.events.on("credential.created", retain_unknown)
    runtime.events.on("payment.failed", failed.append)
    inner = MockTransport([payment_required()])
    transport = SyncPaymentTransport(runtime=runtime, inner=inner)
    try:
        with pytest.raises(PaymentOutcomeUnknownError) as raised:
            transport.handle_request(request)
    finally:
        transport.close()
        runtime.close()

    assert raised.value.credential is retained
    assert failed[0]["credential"] is retained
    assert len(inner.requests) == 1


@pytest.mark.parametrize("status", [200, 402, 503])
def test_event_abort_closes_unreturned_response_and_preserves_portal(status: int) -> None:
    class Abort(BaseException):
        pass

    stream = TrackingStream([b"body"])
    runtime = OwnedPaymentRuntime([MockMethod()])
    transport = SyncPaymentTransport(
        runtime=runtime,
        inner=MockTransport([payment_required(), httpx.Response(status, stream=stream)]),
    )
    event = "payment.response" if status == 200 else "payment.failed"
    unsubscribe = runtime.events.on(event, lambda _payload: (_ for _ in ()).throw(Abort()))
    try:
        with pytest.raises(Abort):
            transport.handle_request(httpx.Request("GET", "https://example.com"))
        unsubscribe()
        assert runtime.emit_event_sync("still.alive", {}) is None
    finally:
        transport.close()
        runtime.close()

    assert stream.closed


def test_event_abort_closes_unpayable_challenge_response() -> None:
    class Abort(BaseException):
        pass

    stream = TrackingStream([b"explanation"])
    transport = SyncPaymentTransport(
        methods=[MockMethod()],
        inner=MockTransport(
            [
                httpx.Response(
                    402,
                    headers={"www-authenticate": "Payment invalid-base64!!"},
                    stream=stream,
                )
            ]
        ),
    )
    transport.on_payment_failed(lambda _payload: (_ for _ in ()).throw(Abort()))
    try:
        with pytest.raises(Abort):
            transport.handle_request(httpx.Request("GET", "https://example.com"))
    finally:
        transport.close()

    assert stream.closed


def test_handler_can_supply_credential() -> None:
    method = MockMethod()
    credential = make_credential({"hash": "0xevent"}, challenge_id="test-id")
    inner = MockTransport([payment_required(), httpx.Response(200, content=b"paid")])
    transport = SyncPaymentTransport(methods=[method], inner=inner)
    events: list[str] = []
    transport.on_challenge_received(lambda _payload: credential)
    transport.on_credential_created(lambda _payload: events.append("credential"))
    transport.on_payment_response(lambda _payload: events.append("response"))
    try:
        response = transport.handle_request(httpx.Request("GET", "https://example.com"))
    finally:
        transport.close()

    assert response.status_code == 200
    assert events == ["credential", "response"]
    method.create_credential.assert_not_called()


def test_transport_ownership_and_validation() -> None:
    with pytest.raises(ValueError, match="methods or runtime"):
        SyncPaymentTransport()

    plain = PaymentRuntime()
    with pytest.raises(TypeError, match="OwnedPaymentRuntime"):
        SyncPaymentTransport(runtime=plain)  # type: ignore[arg-type]

    runtime = OwnedPaymentRuntime()
    with pytest.raises(ValueError, match="either methods/events or runtime"):
        SyncPaymentTransport(methods=[], runtime=runtime)

    inner = MockTransport([])
    borrowed = SyncPaymentTransport(runtime=runtime, inner=inner)
    runtime.start()
    borrowed.close()
    assert runtime.emit_event_sync("still.open", {}) is None
    runtime.close()


def test_owned_runtime_closes_when_inner_close_fails() -> None:
    error = RuntimeError("inner close failed")

    class FailingCloseTransport(MockTransport):
        def close(self) -> None:
            super().close()
            raise error

    transport = SyncPaymentTransport(methods=[], inner=FailingCloseTransport([]))
    runtime = transport._runtime
    with pytest.raises(RuntimeError) as raised:
        transport.close()

    assert raised.value is error
    with pytest.raises(RuntimeError, match="closed"):
        runtime.start()


def test_close_waits_for_committed_retry() -> None:
    retry_started = threading.Event()
    retry_release = threading.Event()
    closed = threading.Event()
    events: list[str] = []
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return payment_required()
        retry_started.set()
        assert retry_release.wait(1)
        return httpx.Response(200, content=b"paid")

    runtime = OwnedPaymentRuntime([MockMethod()])
    runtime.events.on("payment.response", lambda _payload: events.append("response"))
    transport = SyncPaymentTransport(runtime=runtime, inner=httpx.MockTransport(handler))
    responses: list[httpx.Response] = []
    request_thread = threading.Thread(
        target=lambda: responses.append(
            transport.handle_request(httpx.Request("GET", "https://example.com"))
        )
    )
    request_thread.start()
    assert retry_started.wait(1)
    close_thread = threading.Thread(target=lambda: (runtime.close(), closed.set()))
    close_thread.start()
    assert not closed.wait(0.05)

    retry_release.set()
    request_thread.join(timeout=1)
    close_thread.join(timeout=1)
    transport.close()

    assert responses[0].status_code == 200
    assert closed.is_set()
    assert events == ["response"]


def test_concurrent_sync_clients_share_atomic_ledger() -> None:
    method = MockMethod()
    runtime = OwnedPaymentRuntime([method]).start()
    barrier = threading.Barrier(2)
    duplicate_seen = threading.Event()
    begin = runtime._begin_http_payment

    def synchronized_begin(value: Challenge, request: httpx.Request):
        barrier.wait(timeout=1)
        try:
            attempt = begin(value, request)
        except PaymentOutcomeUnknownError:
            duplicate_seen.set()
            raise
        assert duplicate_seen.wait(1)
        return attempt

    runtime._begin_http_payment = synchronized_begin  # type: ignore[method-assign]
    transports = [
        SyncPaymentTransport(
            runtime=runtime,
            inner=MockTransport([payment_required(), httpx.Response(200, content=b"paid")]),
        )
        for _ in range(2)
    ]
    responses: list[httpx.Response] = []
    errors: list[BaseException] = []

    def send(transport: SyncPaymentTransport) -> None:
        try:
            responses.append(transport.handle_request(httpx.Request("GET", "https://example.com")))
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=send, args=(transport,)) for transport in transports]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=1)
        assert not thread.is_alive()
    for transport in transports:
        transport.close()
    runtime.close()

    assert len(responses) == 1
    assert responses[0].status_code == 200
    assert len(errors) == 1
    assert isinstance(errors[0], PaymentOutcomeUnknownError)
    method.create_credential.assert_awaited_once()
