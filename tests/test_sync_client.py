"""Tests for synchronous payment-aware HTTP clients."""

from __future__ import annotations

import asyncio
import threading
from http.cookies import SimpleCookie
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.client import SyncPaymentTransport
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
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

    def test_paid_retry_applies_and_propagates_challenge_cookies(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if "authorization" not in request.headers:
                return httpx.Response(
                    402,
                    headers=[
                        (
                            "www-authenticate",
                            challenge().to_www_authenticate("example.com"),
                        ),
                        ("set-cookie", "session=new; Path=/"),
                        ("set-cookie", "payment_nonce=nonce-1; Path=/"),
                    ],
                )
            return httpx.Response(
                200,
                headers={"set-cookie": "final_cookie=ok; Path=/"},
                content=b"paid",
            )

        transport = SyncPaymentTransport(
            methods=[MockMethod()],
            inner=httpx.MockTransport(handler),
        )
        with httpx.Client(transport=transport) as client:
            client.cookies.set("session", "old", domain="example.com", path="/")
            response = client.get("https://example.com/paid")

            assert response.status_code == 200
            assert requests[0].headers["cookie"] == "session=old"
            retry_cookies = SimpleCookie(requests[1].headers["cookie"])
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

    @pytest.mark.parametrize("race", ["operation", "circuit"])
    def test_send_boundary_unknown_emits_payment_failed(self, race: str) -> None:
        from mpp.runtime import _HTTPX_OPERATIONS

        runtime = PaymentRuntime([MockMethod()], max_unknown_outcomes=1)
        request = httpx.Request("GET", "https://example.com")

        def trip_guard(_payload: Any) -> None:
            token = _HTTPX_OPERATIONS.set(None)
            try:
                blockers = (
                    [("blocker", request.url)]
                    if race == "operation"
                    else [
                        ("blocker-1", httpx.URL("https://example.com/1")),
                        ("blocker-2", httpx.URL("https://example.com/2")),
                    ]
                )
                for identifier, url in blockers:
                    blocker_request = httpx.Request("GET", url)
                    blocker = runtime._begin_http_payment(
                        challenge(id=identifier),
                        blocker_request,
                    )
                    runtime._mark_http_payment_sent(blocker, blocker_request)
                    runtime._mark_http_payment_unknown(blocker, TimeoutError("lost"))
            finally:
                _HTTPX_OPERATIONS.reset(token)

        events: list[str] = []
        runtime.events.on("credential.created", trip_guard)
        runtime.events.on("*", lambda event: events.append(event.name))
        inner = MockTransport([payment_required()])
        transport = SyncPaymentTransport(runtime=runtime, inner=inner)
        try:
            with pytest.raises(PaymentOutcomeUnknownError):
                transport.handle_request(request)
        finally:
            transport.close()
            runtime.close()

        assert len(inner.requests) == 1
        assert events == ["challenge.received", "credential.created", "payment.failed"]

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
        transport = runtime.sync_payment_transport(inner=inner)
        try:
            runtime.create_credential_sync(challenge(), method)
            transport.close()
            runtime.create_credential_sync(challenge(), method)
        finally:
            transport.close()
            runtime.close()

        assert inner.closed

    def test_requires_methods_or_runtime(self) -> None:
        with pytest.raises(ValueError, match="Pass methods or runtime"):
            SyncPaymentTransport()

    def test_rejects_runtime_with_methods_or_events(self) -> None:
        runtime = PaymentRuntime([])
        try:
            with pytest.raises(ValueError, match="either methods/events or runtime"):
                SyncPaymentTransport(methods=[], runtime=runtime)
            with pytest.raises(ValueError, match="either methods/events or runtime"):
                SyncPaymentTransport(events=runtime.events, runtime=runtime)
        finally:
            runtime.close()

    def test_close_finalizes_owned_runtime_when_inner_close_fails(self) -> None:
        error = RuntimeError("inner close failed")

        class FailingCloseTransport(MockTransport):
            def close(self) -> None:
                super().close()
                raise error

        inner = FailingCloseTransport([])
        transport = SyncPaymentTransport(methods=[], inner=inner)
        runtime = transport._runtime

        with pytest.raises(RuntimeError) as raised:
            transport.close()

        assert raised.value is error
        assert inner.closed
        with pytest.raises(RuntimeError, match="closed"):
            runtime.start()


class TestSyncCloseLease:
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
