"""Tests for client-side transport."""

import asyncio
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

from mpp import Challenge, Credential
from mpp.client import Client, PaymentTransport, get, post, request
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
from mpp.runtime import PaymentRuntime
from tests import make_credential


class MockMethod:
    """Mock payment method for testing."""

    name = "tempo"

    def __init__(self) -> None:
        self.create_credential = AsyncMock(
            return_value=make_credential(
                payload={"hash": "0xabc"},
                challenge_id="test-id",
            )
        )


class MockTransport(httpx.AsyncBaseTransport):
    """Mock transport that returns configurable responses."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []
        self._index = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        response = self.responses[self._index]
        self._index += 1
        return response

    async def aclose(self) -> None:
        pass


class ConsumingTransport(MockTransport):
    def __init__(self, responses: list[httpx.Response]) -> None:
        super().__init__(responses)
        self.bodies: list[bytes] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        stream = cast(httpx.AsyncByteStream, request.stream)
        self.bodies.append(b"".join([chunk async for chunk in stream]))
        response = self.responses[self._index]
        self._index += 1
        return response


class TrackingStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, broken: bool = False) -> None:
        self.chunks = chunks
        self.broken = broken
        self.started = False
        self.closed = False

    async def __aiter__(self):
        self.started = True
        if self.broken:
            raise httpx.ReadError("body lost")
        for chunk in self.chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def payment_required(identifier: str = "test-id", **kwargs: Any) -> httpx.Response:
    challenge = Challenge(
        id=identifier,
        method="tempo",
        intent="charge",
        request={"amount": "1000"},
        **kwargs,
    )
    return httpx.Response(
        402,
        headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
    )


class TestPaymentTransport:
    @pytest.mark.asyncio
    async def test_passes_through_non_402(self) -> None:
        """Should pass through non-402 responses unchanged."""
        inner = MockTransport([httpx.Response(200, content=b'{"data": "ok"}')])
        transport = PaymentTransport(methods=[], inner=inner)

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 200
        assert len(inner.requests) == 1

    @pytest.mark.asyncio
    async def test_handles_402_with_matching_method(self) -> None:
        """Should retry 402 with credentials when method matches."""
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")

        inner = ConsumingTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
                httpx.Response(200, content=b'{"data": "ok"}'),
            ]
        )

        method = MockMethod()
        transport = PaymentTransport(methods=[method], inner=inner)

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 200
        assert len(inner.requests) == 2

        retry_request = inner.requests[1]
        assert "Authorization" in retry_request.headers
        assert retry_request.headers["Authorization"].startswith("Payment ")

        method.create_credential.assert_called_once()

    @pytest.mark.asyncio
    async def test_paid_retry_replays_request_body(self) -> None:
        """The paid retry must carry the original bytes request body.

        Regression: the retry previously reused the already-consumed request
        stream, so a POST body was dropped on the (paying) retry.
        """
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")

        inner = ConsumingTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
                httpx.Response(200, content=b'{"data": "ok"}'),
            ]
        )
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        body = b'{"prompt": "expensive question"}'
        request = httpx.Request("POST", "https://example.com", content=body)
        await transport.handle_async_request(request)

        assert len(inner.requests) == 2
        retry_request = inner.requests[1]
        assert retry_request.content == body
        assert retry_request.headers["content-length"] == str(len(body))

    @pytest.mark.asyncio
    async def test_paid_retry_replays_multipart_body(self) -> None:
        """The paid retry must carry the original multipart (files=) body."""
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")

        inner = ConsumingTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
                httpx.Response(200, content=b'{"data": "ok"}'),
            ]
        )
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        file_content = b"hello from file"
        request = httpx.Request(
            "POST",
            "https://example.com",
            files={"upload": ("report.txt", file_content, "text/plain")},
        )
        await transport.handle_async_request(request)

        assert len(inner.requests) == 2
        initial_body, retry_body = inner.bodies
        assert retry_body == initial_body
        assert b"hello from file" in retry_body
        assert b"report.txt" in retry_body

    @pytest.mark.asyncio
    async def test_paid_retry_replays_put_body(self) -> None:
        """The paid retry must carry the original body for PUT requests."""
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")

        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
                httpx.Response(200, content=b'{"updated": true}'),
            ]
        )
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        body = b'{"name": "updated"}'
        request = httpx.Request("PUT", "https://example.com/item/1", content=body)
        await transport.handle_async_request(request)

        assert len(inner.requests) == 2
        retry_request = inner.requests[1]
        assert retry_request.method == "PUT"
        assert retry_request.content == body
        assert retry_request.headers["content-length"] == str(len(body))

    @pytest.mark.asyncio
    async def test_paid_retry_replays_patch_body(self) -> None:
        """The paid retry must carry the original body for PATCH requests."""
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")

        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
                httpx.Response(200, content=b'{"patched": true}'),
            ]
        )
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        body = b'{"status": "active"}'
        request = httpx.Request("PATCH", "https://example.com/item/1", content=body)
        await transport.handle_async_request(request)

        assert len(inner.requests) == 2
        retry_request = inner.requests[1]
        assert retry_request.method == "PATCH"
        assert retry_request.content == body
        assert retry_request.headers["content-length"] == str(len(body))

    @pytest.mark.asyncio
    async def test_paid_retry_raises_for_consumed_streaming_body(self) -> None:
        inner = ConsumingTransport([payment_required()])
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        async def async_body_gen():
            yield b"chunk1"
            yield b"chunk2"

        request = httpx.Request("POST", "https://example.com", content=async_body_gen())
        with pytest.raises(PaymentError, match="Streaming request bodies"):
            await transport.handle_async_request(request)

        assert inner.bodies == [b"chunk1chunk2"]
        assert len(inner.requests) == 1

    @pytest.mark.asyncio
    async def test_free_streaming_body_passes_through(self) -> None:
        inner = ConsumingTransport([httpx.Response(200, content=b"free")])
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        async def body():
            yield b"streamed"

        response = await transport.handle_async_request(
            httpx.Request("POST", "https://example.com", content=body())
        )

        assert response.content == b"free"
        assert inner.bodies == [b"streamed"]

    @pytest.mark.asyncio
    async def test_free_stream_is_not_read_by_wrapper(self) -> None:
        stream = TrackingStream([b"streamed"])
        transport = PaymentTransport(
            methods=[MockMethod()],
            inner=MockTransport([httpx.Response(200, content=b"free")]),
        )

        response = await transport.handle_async_request(
            httpx.Request("POST", "https://example.com", content=stream)
        )

        assert response.content == b"free"
        assert not stream.started

    @pytest.mark.asyncio
    async def test_duplicate_method_names_still_match_intent(self) -> None:
        class SubscriptionMethod(MockMethod):
            intents = {"subscription": None}

        first = SubscriptionMethod()
        second = MockMethod()
        transport = PaymentTransport(
            methods=[first, second],
            inner=MockTransport([payment_required(), httpx.Response(200)]),
        )

        await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        first.create_credential.assert_not_awaited()
        second.create_credential.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_emits_client_payment_events(self) -> None:
        """Should emit mppx-compatible client payment lifecycle events."""
        events: list[str] = []
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
                httpx.Response(200, content=b'{"data": "ok"}'),
            ]
        )
        method = MockMethod()
        transport = PaymentTransport(methods=[method], inner=inner)

        transport.on_challenge_received(
            lambda payload: events.append(f"challenge:{payload['challenge'].id}")
        )
        transport.on_credential_created(
            lambda payload: events.append(f"credential:{payload['challenge'].id}")
        )
        transport.on_payment_response(
            lambda payload: events.append(f"response:{payload['response'].status_code}")
        )
        transport.on("*", lambda event: events.append(f"*:{event.name}"))

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 200
        assert events == [
            "challenge:test-id",
            "*:challenge.received",
            "credential:test-id",
            "*:credential.created",
            "response:200",
            "*:payment.response",
        ]

    @pytest.mark.asyncio
    async def test_challenge_received_handler_can_provide_credential(self) -> None:
        """A challenge.received handler can provide the credential used for retry."""
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
                httpx.Response(200, content=b'{"data": "ok"}'),
            ]
        )
        method = MockMethod()
        event_credential = make_credential(payload={"hash": "0xevent"}, challenge_id="event-id")
        transport = PaymentTransport(methods=[method], inner=inner)
        transport.on_challenge_received(lambda payload: event_credential)

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 200
        assert inner.requests[1].headers["Authorization"] == event_credential.to_authorization()
        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_challenge_received_uses_first_returned_credential(self) -> None:
        """Should stop challenge.received handlers after a credential is returned."""
        events: list[str] = []
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
                httpx.Response(200, content=b'{"data": "ok"}'),
            ]
        )
        first_credential = make_credential(payload={"hash": "0xfirst"}, challenge_id="first")
        second_credential = make_credential(payload={"hash": "0xsecond"}, challenge_id="second")
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        def first(payload: object) -> Credential:
            events.append("first")
            return first_credential

        def second(payload: object) -> Credential:
            events.append("second")
            return second_credential

        transport.on_challenge_received(first)
        transport.on_challenge_received(second)

        response = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert response.status_code == 200
        assert events == ["first"]
        assert inner.requests[1].headers["Authorization"] == first_credential.to_authorization()

    @pytest.mark.asyncio
    async def test_returns_402_when_no_matching_method(self) -> None:
        """Should return 402 when no matching method found."""
        failed_payloads: list[dict] = []
        challenge = Challenge(
            id="test-id",
            method="stripe",  # No stripe method configured
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")

        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
            ]
        )

        tempo_method = MockMethod()  # Only tempo configured
        transport = PaymentTransport(methods=[tempo_method], inner=inner)
        transport.on_payment_failed(lambda payload: failed_payloads.append(payload))

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 402
        assert len(inner.requests) == 1
        assert len(failed_payloads) == 1
        payload = failed_payloads[0]
        assert payload["challenge"] is None
        assert len(payload["challenges"]) == 1
        assert payload["challenges"][0].id == challenge.id
        assert payload["challenges"][0].method == challenge.method
        assert payload["credential"] is None
        assert isinstance(payload["error"], ValueError)
        assert payload["method"] is None
        assert payload["request"] is request
        assert payload["response"] is response

    @pytest.mark.asyncio
    async def test_returns_402_without_payment_header(self) -> None:
        """Should return 402 if no Payment WWW-Authenticate header."""
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": "Bearer realm=test"}),
            ]
        )

        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 402

    @pytest.mark.asyncio
    async def test_returns_402_on_parse_error(self) -> None:
        """Should return 402 if challenge cannot be parsed."""
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": "Payment invalid-base64!!"}),
            ]
        )

        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 402

    @pytest.mark.asyncio
    async def test_aclose(self) -> None:
        """Should close inner transport."""
        inner = MockTransport([])
        transport = PaymentTransport(methods=[], inner=inner)
        await transport.aclose()

    @pytest.mark.asyncio
    async def test_skips_expired_challenge(self) -> None:
        """Should return 402 without paying if challenge is expired."""
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires="2020-01-01T00:00:00Z",  # Expired
        )
        www_auth = challenge.to_www_authenticate("example.com")

        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
            ]
        )

        method = MockMethod()
        transport = PaymentTransport(methods=[method], inner=inner)

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 402
        assert len(inner.requests) == 1
        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_multiple_www_authenticate_headers(self) -> None:
        """Should find matching method across multiple WWW-Authenticate headers."""
        tempo_challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        tempo_auth = tempo_challenge.to_www_authenticate("example.com")

        inner = MockTransport(
            [
                httpx.Response(
                    402,
                    headers=[
                        ("www-authenticate", "Bearer realm=test"),
                        ("www-authenticate", tempo_auth),
                    ],
                ),
                httpx.Response(200, content=b'{"data": "ok"}'),
            ]
        )

        method = MockMethod()
        transport = PaymentTransport(methods=[method], inner=inner)

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 200
        assert len(inner.requests) == 2
        method.create_credential.assert_called_once()

    @pytest.mark.asyncio
    async def test_does_not_retry_when_method_rejects_challenge(self) -> None:
        """Should not send an Authorization retry when the method rejects the challenge."""
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000", "methodDetails": {"chainId": 42431}},
        )
        www_auth = challenge.to_www_authenticate("example.com")

        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": www_auth}),
            ]
        )

        method = MockMethod()
        method.create_credential.side_effect = ValueError(
            "Challenge requests chain ID 42431, but client is restricted to 4217"
        )
        transport = PaymentTransport(methods=[method], inner=inner)

        request = httpx.Request("GET", "https://example.com")

        with pytest.raises(ValueError, match="client is restricted to 4217"):
            await transport.handle_async_request(request)

        assert len(inner.requests) == 1
        method.create_credential.assert_called_once()

    @pytest.mark.asyncio
    async def test_emits_payment_failed_when_credential_creation_fails(self) -> None:
        """Should emit payment.failed when automatic payment handling raises."""
        events: list[str] = []
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        www_auth = challenge.to_www_authenticate("example.com")
        inner = MockTransport([httpx.Response(402, headers={"www-authenticate": www_auth})])
        method = MockMethod()
        method.create_credential.side_effect = ValueError("no account")
        transport = PaymentTransport(methods=[method], inner=inner)
        transport.on_payment_failed(
            lambda payload: events.append(
                f"failed:{payload['challenge'].id}:{type(payload['error']).__name__}"
            )
        )

        request = httpx.Request("GET", "https://example.com")
        with pytest.raises(ValueError, match="no account"):
            await transport.handle_async_request(request)

        assert events == ["failed:test-id:ValueError"]

    @pytest.mark.asyncio
    async def test_emits_payment_failed_when_retry_raises(self) -> None:
        """Should emit payment.failed when paid retry raises."""
        events: list[str] = []
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )

        class FailingRetryTransport(MockTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.requests.append(request)
                if len(self.requests) == 1:
                    return httpx.Response(
                        402,
                        headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
                    )
                raise RuntimeError("network failed")

        transport = PaymentTransport(methods=[MockMethod()], inner=FailingRetryTransport([]))
        transport.on_payment_failed(
            lambda payload: events.append(
                f"failed:{payload['challenge'].id}:{type(payload['error']).__name__}"
            )
        )

        with pytest.raises(PaymentOutcomeUnknownError, match="Do not blindly retry") as raised:
            await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert isinstance(raised.value.__cause__, RuntimeError)
        assert events == ["failed:test-id:PaymentOutcomeUnknownError"]


class TestRuntimePaymentTransport:
    @pytest.mark.asyncio
    async def test_explicit_runtime_shares_events_and_survives_transport_close(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        events: list[str] = []
        runtime.events.on("*", lambda event: events.append(event.name))
        transport = runtime.payment_transport(
            MockTransport([payment_required(), httpx.Response(200, content=b"paid")])
        )

        response = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        await transport.aclose()
        await runtime.emit_event("custom", {})

        assert response.content == b"paid"
        assert events == [
            "challenge.received",
            "credential.created",
            "payment.response",
            "custom",
        ]

    @pytest.mark.asyncio
    async def test_implicit_runtime_preserves_method_caller_loop(self) -> None:
        caller_loop = asyncio.get_running_loop()
        loops: list[asyncio.AbstractEventLoop] = []

        class LoopMethod(MockMethod):
            async def create(self, challenge: Challenge) -> Credential:
                loops.append(asyncio.get_running_loop())
                return make_credential({}, challenge_id=challenge.id)

        method = LoopMethod()
        method.create_credential.side_effect = method.create
        transport = PaymentTransport(
            methods=[method],
            inner=MockTransport([payment_required(), httpx.Response(200, content=b"paid")]),
        )

        await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert loops == [caller_loop]

    @pytest.mark.parametrize(
        "allowed_origins",
        [["https://allowed.test:443"], "https://allowed.test:443"],
    )
    @pytest.mark.asyncio
    async def test_origin_policy_is_exact_and_normalizes_default_ports(
        self,
        allowed_origins: list[str] | str,
    ) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method], allowed_origins=allowed_origins)
        blocked = MockTransport([payment_required()])
        allowed = MockTransport([payment_required(), httpx.Response(200, content=b"paid")])

        blocked_response = await runtime.payment_transport(blocked).handle_async_request(
            httpx.Request("GET", "http://allowed.test/resource")
        )
        allowed_response = await runtime.payment_transport(allowed).handle_async_request(
            httpx.Request("GET", "https://allowed.test/resource")
        )

        assert blocked_response.status_code == 402
        assert len(blocked.requests) == 1
        assert allowed_response.status_code == 200
        assert method.create_credential.await_count == 1

    @pytest.mark.asyncio
    async def test_invalid_origin_entries_fail_closed(self) -> None:
        runtime = PaymentRuntime([MockMethod()], allowed_origins=["/relative", "not a url"])
        inner = MockTransport([payment_required()])

        response = await runtime.payment_transport(inner).handle_async_request(
            httpx.Request("GET", "https://example.com")
        )

        assert response.status_code == 402
        assert len(inner.requests) == 1

    def test_rejects_ambiguous_or_missing_configuration(self) -> None:
        runtime = PaymentRuntime()
        with pytest.raises(ValueError, match="methods or runtime"):
            PaymentTransport()
        with pytest.raises(ValueError, match="either methods/events or runtime"):
            PaymentTransport(methods=[], runtime=runtime)
        with pytest.raises(ValueError, match="either methods/events or runtime"):
            PaymentTransport(events=runtime.events, runtime=runtime)

    @pytest.mark.asyncio
    async def test_owned_transport_closes_only_its_runtime(self) -> None:
        owned = PaymentTransport(methods=[], inner=MockTransport([]))
        owned_runtime = owned._runtime
        borrowed_runtime = PaymentRuntime()
        borrowed = borrowed_runtime.payment_transport(MockTransport([]))

        await owned.aclose()
        await borrowed.aclose()

        with pytest.raises(RuntimeError, match="closed"):
            await owned_runtime.astart()
        assert await borrowed_runtime.astart() is borrowed_runtime

    @pytest.mark.asyncio
    async def test_close_requested_during_payment_is_deferred_until_retry_finishes(self) -> None:
        runtime = PaymentRuntime([MockMethod()])
        events: list[str] = []
        runtime.events.on("credential.created", lambda _payload: runtime.close())
        runtime.events.on("payment.response", lambda _payload: events.append("response"))
        transport = runtime.payment_transport(
            MockTransport([payment_required(), httpx.Response(200, content=b"paid")])
        )

        response = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert response.status_code == 200
        assert events == ["response"]
        with pytest.raises(RuntimeError, match="closed"):
            runtime.start()

    @pytest.mark.asyncio
    async def test_closing_runtime_rejects_unrelated_tasks(self) -> None:
        retry_started = asyncio.Event()
        retry_release = asyncio.Event()
        calls = 0

        async def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return payment_required()
            retry_started.set()
            await retry_release.wait()
            return httpx.Response(200, content=b"paid")

        runtime = PaymentRuntime([MockMethod()])
        transport = runtime.payment_transport(httpx.MockTransport(handler))
        request_task = asyncio.create_task(
            transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        )
        await retry_started.wait()
        runtime.close()

        with pytest.raises(RuntimeError, match="closed"):
            await runtime.emit_event("outside", {})
        retry_release.set()

        assert (await request_task).status_code == 200

    @pytest.mark.asyncio
    async def test_close_rejects_child_that_has_not_acquired_its_own_lease(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        child_inner = MockTransport([payment_required("child")])
        child_transport = runtime.payment_transport(child_inner)
        child: asyncio.Task[httpx.Response] | None = None

        def close_after_spawning_child(payload: dict[str, Any]) -> None:
            nonlocal child
            if payload["challenge"].id != "parent":
                return
            child = asyncio.create_task(
                child_transport.handle_async_request(
                    httpx.Request("GET", "https://example.com/child")
                )
            )
            runtime.close()

        runtime.events.on("credential.created", close_after_spawning_child)
        parent_transport = runtime.payment_transport(
            MockTransport([payment_required("parent"), httpx.Response(200, content=b"parent")])
        )

        parent = await parent_transport.handle_async_request(
            httpx.Request("GET", "https://example.com/parent")
        )

        assert child is not None
        with pytest.raises(RuntimeError, match="closed"):
            await child
        assert parent.content == b"parent"
        assert len(child_inner.requests) == 1
        assert method.create_credential.await_count == 1

    @pytest.mark.asyncio
    async def test_close_rejects_nested_payment_in_same_task(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        nested_inner = MockTransport([payment_required("nested")])
        nested = runtime.payment_transport(nested_inner)

        async def close_then_pay(payload: dict[str, Any]) -> None:
            if payload["challenge"].id != "parent":
                return
            runtime.close()
            with pytest.raises(RuntimeError, match="closed"):
                await nested.handle_async_request(
                    httpx.Request("GET", "https://example.com/nested")
                )

        runtime.events.on("credential.created", close_then_pay)
        parent = runtime.payment_transport(
            MockTransport([payment_required("parent"), httpx.Response(200, content=b"parent")])
        )

        response = await parent.handle_async_request(
            httpx.Request("GET", "https://example.com/parent")
        )

        assert response.content == b"parent"
        assert len(nested_inner.requests) == 1
        assert method.create_credential.await_count == 1

    @pytest.mark.asyncio
    async def test_close_waits_for_child_with_its_own_lease(self) -> None:
        method = MockMethod()
        runtime = PaymentRuntime([method])
        child_retry_started = asyncio.Event()
        release_child = asyncio.Event()
        child_calls = 0

        async def child_handler(request: httpx.Request) -> httpx.Response:
            nonlocal child_calls
            child_calls += 1
            if "authorization" not in request.headers:
                return payment_required("child")
            child_retry_started.set()
            await release_child.wait()
            return httpx.Response(200, content=b"child")

        child_transport = runtime.payment_transport(httpx.MockTransport(child_handler))
        child: asyncio.Task[httpx.Response] | None = None

        async def close_after_child_is_leased(payload: dict[str, Any]) -> None:
            nonlocal child
            if payload["challenge"].id != "parent":
                return
            child = asyncio.create_task(
                child_transport.handle_async_request(
                    httpx.Request("GET", "https://example.com/child")
                )
            )
            await child_retry_started.wait()
            runtime.close()
            release_child.set()
            assert (await child).content == b"child"

        runtime.events.on("credential.created", close_after_child_is_leased)
        parent_transport = runtime.payment_transport(
            MockTransport([payment_required("parent"), httpx.Response(200, content=b"parent")])
        )

        parent = await parent_transport.handle_async_request(
            httpx.Request("GET", "https://example.com/parent")
        )

        assert child is not None
        assert parent.content == b"parent"
        assert child_calls == 2
        assert method.create_credential.await_count == 2
        with pytest.raises(RuntimeError, match="closed"):
            runtime.start()


class TestHttpPaymentSafety:
    @pytest.mark.asyncio
    async def test_request_read_abort_closes_challenge_response(self) -> None:
        class Abort(BaseException):
            pass

        class AbortStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                raise Abort
                yield b""  # pragma: no cover

            async def aclose(self) -> None:
                pass

        stream = TrackingStream([b"challenge"])
        challenge = httpx.Response(
            402,
            headers=payment_required().headers,
            stream=stream,
        )
        transport = PaymentTransport(
            methods=[MockMethod()],
            inner=MockTransport([challenge]),
        )

        with pytest.raises(Abort):
            await transport.handle_async_request(
                httpx.Request(
                    "POST",
                    "https://example.com",
                    content=AbortStream(),
                )
            )

        assert stream.closed

    @pytest.mark.asyncio
    async def test_close_racing_with_begin_keeps_payment_attempt_leased(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runtime = PaymentRuntime([MockMethod()])
        begin = runtime._begin_http_payment

        def begin_then_close(challenge: Challenge, request: httpx.Request) -> Any:
            attempt = begin(challenge, request)
            runtime.close()
            return attempt

        monkeypatch.setattr(runtime, "_begin_http_payment", begin_then_close)
        inner = MockTransport([payment_required(), httpx.Response(200, content=b"paid")])

        response = await runtime.payment_transport(inner).handle_async_request(
            httpx.Request("GET", "https://example.com")
        )

        assert response.status_code == 200
        assert all("mpp.payment_attempt" not in request.extensions for request in inner.requests)
        with pytest.raises(RuntimeError, match="closed"):
            await runtime.emit_event("after", {})

    @pytest.mark.asyncio
    async def test_retry_construction_failure_discards_unsent_attempt(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mpp.client._http import _HttpPayment

        def fail_retry(_payment: _HttpPayment, _authorization: str) -> httpx.Request:
            raise RuntimeError("retry construction failed")

        monkeypatch.setattr(_HttpPayment, "retry_request", fail_retry)
        method = MockMethod()
        runtime = PaymentRuntime([method])
        failed: list[dict[str, Any]] = []
        runtime.events.on("payment.failed", failed.append)
        inner = MockTransport([payment_required(), payment_required()])
        transport = runtime.payment_transport(inner)

        for _ in range(2):
            with pytest.raises(RuntimeError, match="retry construction failed"):
                await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert len(inner.requests) == 2
        assert method.create_credential.await_count == 2
        assert len(failed) == 2

    @pytest.mark.asyncio
    async def test_response_processing_failure_keeps_known_outcome(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fail_cookies(_source: httpx.Response, _target: httpx.Response) -> None:
            raise RuntimeError("cookie propagation failed")

        monkeypatch.setattr(
            "mpp.client.transport._propagate_response_cookies",
            fail_cookies,
        )
        paid_stream = TrackingStream([b"paid"])
        method = MockMethod()
        transport = PaymentRuntime([method]).payment_transport(
            MockTransport(
                [
                    payment_required(),
                    httpx.Response(200, stream=paid_stream),
                    payment_required(),
                    httpx.Response(200, content=b"again"),
                ]
            )
        )

        with pytest.raises(RuntimeError, match="cookie propagation failed"):
            await transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        monkeypatch.undo()
        response = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert paid_stream.closed
        assert response.content == b"again"
        assert method.create_credential.await_count == 2

    @pytest.mark.parametrize("race", ["operation", "circuit"])
    @pytest.mark.asyncio
    async def test_send_boundary_unknown_emits_payment_failed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        race: str,
    ) -> None:
        if race == "circuit":
            monkeypatch.setattr("mpp.client._http._MAX_UNRECONCILED_OUTCOMES", 1)
        runtime = PaymentRuntime([MockMethod()])
        request = httpx.Request("GET", "https://example.com")

        def trip_guard(_payload: dict[str, Any]) -> None:
            blockers = (
                [("blocker", request.url)]
                if race == "operation"
                else [("blocker", httpx.URL("https://example.com/other"))]
            )
            for identifier, url in blockers:
                blocker_request = httpx.Request("GET", url)
                blocker = runtime._begin_http_payment(
                    Challenge(
                        id=identifier,
                        method="tempo",
                        intent="charge",
                        request={},
                    ),
                    blocker_request,
                )
                blocker.credential = make_credential(
                    {"retained": True},
                    challenge_id=identifier,
                )
                blocker.mark_sent(blocker_request)
                blocker.unknown(TimeoutError("response lost"))

        failed: list[dict[str, Any]] = []
        runtime.events.on("credential.created", trip_guard)
        runtime.events.on("payment.failed", failed.append)
        inner = MockTransport([payment_required()])

        with pytest.raises(PaymentOutcomeUnknownError):
            await runtime.payment_transport(inner).handle_async_request(request)

        assert len(inner.requests) == 1
        assert isinstance(failed[0]["error"], PaymentOutcomeUnknownError)
        assert failed[0]["challenge"].id == "test-id"
        assert failed[0]["credential"] == failed[0]["error"].credential
        assert failed[0]["credential"].payload == {"retained": True}

    @pytest.mark.parametrize("idempotency_key", [None, "same-operation"])
    @pytest.mark.asyncio
    async def test_concurrent_requests_only_share_active_operation_with_idempotency_key(
        self,
        idempotency_key: str | None,
    ) -> None:
        first_retry = asyncio.Event()
        second_retry = asyncio.Event()
        release = asyncio.Event()
        challenge_calls = paid_calls = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal challenge_calls, paid_calls
            if "authorization" not in request.headers:
                challenge_calls += 1
                return payment_required(f"challenge-{challenge_calls}")
            paid_calls += 1
            (first_retry if paid_calls == 1 else second_retry).set()
            await release.wait()
            return httpx.Response(200, content=b"paid")

        transport = PaymentRuntime([MockMethod()]).payment_transport(httpx.MockTransport(handler))
        headers = {"idempotency-key": idempotency_key} if idempotency_key else {}

        def request() -> httpx.Request:
            return httpx.Request(
                "POST",
                "https://example.com/resource",
                headers=headers,
                content=b"same body",
            )

        first = asyncio.create_task(transport.handle_async_request(request()))
        await first_retry.wait()
        second = asyncio.create_task(transport.handle_async_request(request()))

        try:
            if idempotency_key:
                with pytest.raises(PaymentOutcomeUnknownError):
                    await second
                assert paid_calls == 1
            else:
                await asyncio.wait_for(second_retry.wait(), timeout=1)
        finally:
            release.set()

        assert (await first).status_code == 200
        if not idempotency_key:
            assert (await second).status_code == 200

    @pytest.mark.asyncio
    async def test_unknown_operation_blocks_a_new_challenge_for_same_request(self) -> None:
        challenge_calls = paid_calls = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal challenge_calls, paid_calls
            if "authorization" not in request.headers:
                challenge_calls += 1
                return payment_required(f"challenge-{challenge_calls}")
            paid_calls += 1
            raise httpx.WriteError("response lost")

        method = MockMethod()
        transport = PaymentRuntime([method]).payment_transport(httpx.MockTransport(handler))

        def request() -> httpx.Request:
            return httpx.Request(
                "POST",
                "https://example.com/resource",
                content=b"same body",
            )

        with pytest.raises(PaymentOutcomeUnknownError):
            await transport.handle_async_request(request())
        with pytest.raises(PaymentOutcomeUnknownError):
            await transport.handle_async_request(request())

        assert challenge_calls == 2
        assert paid_calls == 1
        method.create_credential.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_challenge_cookies_apply_to_retry_and_reach_caller(self) -> None:
        initial = httpx.Response(
            402,
            headers=[
                ("www-authenticate", payment_required().headers["www-authenticate"]),
                ("set-cookie", "session=new; Path=/"),
                ("set-cookie", "nonce=one; Path=/"),
            ],
        )
        paid = httpx.Response(200, headers={"set-cookie": "paid=yes; Path=/"}, content=b"ok")
        inner = MockTransport([initial, paid])
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        response = await transport.handle_async_request(
            httpx.Request(
                "GET",
                "https://example.com/resource",
                headers={"cookie": "session=old; keep=yes"},
            )
        )

        retry_cookie = inner.requests[1].headers["cookie"]
        assert "session=new" in retry_cookie
        assert "nonce=one" in retry_cookie
        assert "keep=yes" in retry_cookie
        assert "session=old" not in retry_cookie
        assert response.headers.get_list("set-cookie") == [
            "session=new; Path=/",
            "nonce=one; Path=/",
            "paid=yes; Path=/",
        ]

    @pytest.mark.asyncio
    async def test_combined_authentication_header_finds_payment_challenge(self) -> None:
        payment = Challenge(
            id="combined",
            method="tempo",
            intent="charge",
            request={"amount": "1000", "currency": "USD"},
        ).to_www_authenticate("example.com")
        inner = MockTransport(
            [
                httpx.Response(
                    402,
                    headers={"www-authenticate": f'Bearer realm="api", {payment}'},
                ),
                httpx.Response(200, content=b"paid"),
            ]
        )

        response = await PaymentTransport(
            methods=[MockMethod()],
            inner=inner,
        ).handle_async_request(httpx.Request("GET", "https://example.com"))

        assert response.status_code == 200
        assert len(inner.requests) == 2

    @pytest.mark.asyncio
    async def test_valid_offer_is_preferred_over_an_expired_offer(self) -> None:
        expired = Challenge(
            id="expired",
            method="tempo",
            intent="charge",
            request={},
            expires="2020-01-01T00:00:00Z",
        )
        current = Challenge(id="current", method="tempo", intent="charge", request={})
        inner = MockTransport(
            [
                httpx.Response(
                    402,
                    headers=[
                        ("www-authenticate", expired.to_www_authenticate("example.com")),
                        ("www-authenticate", current.to_www_authenticate("example.com")),
                    ],
                ),
                httpx.Response(200, content=b"paid"),
            ]
        )
        method = MockMethod()

        await PaymentTransport(methods=[method], inner=inner).handle_async_request(
            httpx.Request("GET", "https://example.com")
        )

        assert method.create_credential.await_args is not None
        assert method.create_credential.await_args.args[0].id == "current"

    @pytest.mark.asyncio
    async def test_http_matching_rejects_wrong_intent(self) -> None:
        challenge = Challenge(
            id="subscription",
            method="tempo",
            intent="subscription",
            request={},
        )
        inner = MockTransport(
            [
                httpx.Response(
                    402,
                    headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
                ),
                httpx.Response(200, content=b"paid"),
            ]
        )

        method = MockMethod()
        response = await PaymentTransport(
            methods=[method],
            inner=inner,
        ).handle_async_request(httpx.Request("GET", "https://example.com"))

        assert response.status_code == 402
        method.create_credential.assert_not_awaited()

    @pytest.mark.parametrize("blocked", ["missing", "disallowed"])
    @pytest.mark.asyncio
    async def test_nonpayable_402_body_stays_lazy(self, blocked: str) -> None:
        stream = TrackingStream([b"explanation"])
        response = (
            httpx.Response(402, stream=stream)
            if blocked == "missing"
            else httpx.Response(
                402,
                headers=payment_required().headers,
                stream=stream,
            )
        )
        runtime = PaymentRuntime(
            [MockMethod()],
            allowed_origins=[] if blocked == "disallowed" else None,
        )

        result = await runtime.payment_transport(MockTransport([response])).handle_async_request(
            httpx.Request("GET", "https://example.com")
        )

        assert result is response
        assert not stream.started
        assert not stream.closed

    @pytest.mark.asyncio
    async def test_redirected_challenge_uses_response_request_everywhere(self) -> None:
        original = httpx.Request("GET", "https://start.test")
        challenged = httpx.Request("POST", "https://paid.test/resource", content=b"body")
        challenge_response = payment_required()
        challenge_response.request = challenged
        inner = MockTransport([challenge_response, httpx.Response(200, content=b"paid")])
        runtime = PaymentRuntime([MockMethod()], allowed_origins=["https://paid.test"])
        failed: list[dict[str, Any]] = []
        runtime.events.on("payment.failed", failed.append)

        response = await runtime.payment_transport(inner).handle_async_request(original)

        assert response.status_code == 200
        assert inner.requests[1].method == "POST"
        assert inner.requests[1].url == challenged.url
        assert inner.requests[1].content == b"body"

    @pytest.mark.asyncio
    async def test_redirect_cannot_trigger_a_second_payment(self) -> None:
        requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.path == "/start":
                if "authorization" not in request.headers:
                    return payment_required("first")
                return httpx.Response(302, headers={"location": "/next"})
            return payment_required("second")

        method = MockMethod()
        transport = PaymentRuntime([method]).payment_transport(httpx.MockTransport(handler))
        async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
            response = await client.get("https://example.com/start")

        assert response.status_code == 402
        assert [request.url.path for request in requests] == ["/start", "/start", "/next"]
        method.create_credential.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unmatched_failure_abort_closes_challenge_response(self) -> None:
        class Abort(BaseException):
            pass

        stream = TrackingStream([b"challenge"])
        response = httpx.Response(
            402,
            headers=payment_required().headers,
            stream=stream,
        )
        runtime = PaymentRuntime([])
        runtime.events.on("payment.failed", lambda _payload: (_ for _ in ()).throw(Abort()))

        with pytest.raises(Abort):
            await runtime.payment_transport(MockTransport([response])).handle_async_request(
                httpx.Request("GET", "https://example.com")
            )

        assert stream.closed

    @pytest.mark.asyncio
    async def test_matching_failure_closes_challenge_response(self) -> None:
        class BrokenRuntime(PaymentRuntime):
            def match_challenge(self, *args: Any, **kwargs: Any):
                raise RuntimeError("match failed")

        stream = TrackingStream([b"challenge"])
        response = httpx.Response(402, headers=payment_required().headers, stream=stream)
        transport = BrokenRuntime([MockMethod()]).payment_transport(MockTransport([response]))

        with pytest.raises(RuntimeError, match="match failed"):
            await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert stream.closed

    @pytest.mark.asyncio
    async def test_paid_response_event_abort_closes_response(self) -> None:
        class Abort(BaseException):
            pass

        stream = TrackingStream([b"paid"])
        transport = PaymentTransport(
            methods=[MockMethod()],
            inner=MockTransport([payment_required(), httpx.Response(200, stream=stream)]),
        )
        transport.on_payment_response(lambda _payload: (_ for _ in ()).throw(Abort()))

        with pytest.raises(Abort):
            await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert stream.closed

    @pytest.mark.parametrize("terminal", ["complete", "error", "close"])
    @pytest.mark.asyncio
    async def test_success_status_completes_payment_before_body(self, terminal: str) -> None:
        stream = TrackingStream([b"paid"], broken=terminal == "error")
        inner = MockTransport(
            [
                payment_required(),
                httpx.Response(200, stream=stream),
                payment_required(),
                httpx.Response(200, content=b"again"),
            ]
        )
        method = MockMethod()
        runtime = PaymentRuntime([method])
        transport = runtime.payment_transport(inner)
        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        if terminal == "complete":
            assert await response.aread() == b"paid"
            again = await transport.handle_async_request(
                httpx.Request("GET", "https://example.com")
            )
            assert again.status_code == 200
            assert method.create_credential.await_count == 2
            return
        if terminal == "error":
            with pytest.raises(httpx.ReadError):
                await response.aread()
        else:
            await response.aclose()

        again = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        assert again.status_code == 200
        assert method.create_credential.await_count == 2

    @pytest.mark.asyncio
    async def test_repeated_challenge_after_credential_is_unknown(self) -> None:
        method = MockMethod()
        transport = PaymentTransport(
            methods=[method],
            inner=MockTransport([payment_required(), payment_required()]),
        )

        with pytest.raises(PaymentOutcomeUnknownError, match="Do not blindly retry"):
            await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        method.create_credential.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_error_response_retains_unknown_outcome(self) -> None:
        runtime = PaymentRuntime([MockMethod()])
        inner = MockTransport(
            [
                payment_required(),
                httpx.Response(503, content=b"unavailable"),
                payment_required(),
            ]
        )
        transport = runtime.payment_transport(inner)
        failed: list[dict[str, Any]] = []
        runtime.events.on("payment.failed", failed.append)

        response = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        with pytest.raises(PaymentOutcomeUnknownError):
            await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert response.status_code == 503
        assert isinstance(failed[0]["error"], PaymentOutcomeUnknownError)

    @pytest.mark.asyncio
    async def test_reset_allows_reusing_the_same_request(self) -> None:
        paid_calls = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal paid_calls
            if "authorization" not in request.headers:
                return payment_required(f"challenge-{paid_calls}")
            paid_calls += 1
            if paid_calls == 1:
                raise httpx.WriteError("response lost")
            return httpx.Response(200, content=b"paid")

        runtime = PaymentRuntime([MockMethod()])
        transport = runtime.payment_transport(httpx.MockTransport(handler))
        request = httpx.Request(
            "POST",
            "https://example.com/resource",
            content=b"same body",
        )

        with pytest.raises(PaymentOutcomeUnknownError):
            await transport.handle_async_request(request)
        runtime.reset_unknown_outcomes(reconciled=True)

        response = await transport.handle_async_request(request)

        assert response.content == b"paid"
        assert paid_calls == 2

    @pytest.mark.asyncio
    async def test_only_originating_runtime_can_reconcile_request_marker(self) -> None:
        first_method = MockMethod()
        first_runtime = PaymentRuntime([first_method])
        first_runtime.reset_unknown_outcomes(reconciled=True)

        async def lose_paid_response(request: httpx.Request) -> httpx.Response:
            if "authorization" in request.headers:
                raise httpx.WriteError("response lost")
            return payment_required("first")

        request = httpx.Request(
            "POST",
            "https://example.com/resource",
            content=b"same body",
        )
        with pytest.raises(PaymentOutcomeUnknownError):
            await first_runtime.payment_transport(
                httpx.MockTransport(lose_paid_response)
            ).handle_async_request(request)

        second_method = MockMethod()
        second_inner = MockTransport(
            [
                payment_required("second"),
                payment_required("second"),
                httpx.Response(200, content=b"paid"),
            ]
        )
        second_transport = PaymentRuntime([second_method]).payment_transport(second_inner)

        with pytest.raises(PaymentOutcomeUnknownError):
            await second_transport.handle_async_request(request)
        second_method.create_credential.assert_not_awaited()

        first_runtime.reset_unknown_outcomes(reconciled=True)
        response = await second_transport.handle_async_request(request)

        assert response.content == b"paid"
        second_method.create_credential.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bounded_unknown_outcomes_trip_and_reset_circuit(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("mpp.client._http._MAX_UNRECONCILED_OUTCOMES", 1)

        class FailingPaidTransport(httpx.AsyncBaseTransport):
            def __init__(self) -> None:
                self.requests: list[httpx.Request] = []

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.requests.append(request)
                if "authorization" in request.headers:
                    raise httpx.WriteError("response lost")
                return payment_required(request.url.path)

        method = MockMethod()
        runtime = PaymentRuntime([method])
        inner = FailingPaidTransport()
        transport = runtime.payment_transport(inner)

        with pytest.raises(PaymentOutcomeUnknownError):
            await transport.handle_async_request(
                httpx.Request("POST", "https://example.com/one", content="one")
            )
        with pytest.raises(PaymentOutcomeUnknownError):
            await transport.handle_async_request(
                httpx.Request("POST", "https://example.com/two", content="two")
            )
        assert method.create_credential.await_count == 1

        with pytest.raises(ValueError, match="externally reconciled"):
            runtime.reset_unknown_outcomes(reconciled=False)
        runtime.reset_unknown_outcomes(reconciled=True)
        with pytest.raises(PaymentOutcomeUnknownError):
            await transport.handle_async_request(
                httpx.Request("POST", "https://example.com/two", content="two")
            )
        assert method.create_credential.await_count == 2


@pytest.mark.parametrize(
    ("set_cookie", "url", "expected"),
    [
        ("session=; Max-Age=0; Path=/", "https://example.com/public", False),
        ("session=; Max-Age=0; Path=/admin", "https://example.com/public", True),
        ("session=new; Secure; Path=/", "http://example.com/public", True),
        ("session=new; Domain=other.test; Path=/", "https://example.com/public", True),
    ],
)
def test_challenge_cookie_scope(
    set_cookie: str,
    url: str,
    expected: bool,
) -> None:
    from mpp.client._http import _apply_response_cookies

    source = httpx.Request("GET", url)
    response = httpx.Response(402, headers={"set-cookie": set_cookie}, request=source)
    retry = httpx.Request("GET", url, headers={"cookie": "session=old; keep=yes"})

    _apply_response_cookies(response, source, retry)

    assert ("session=old" in retry.headers["cookie"]) is expected
    assert "keep=yes" in retry.headers["cookie"]


class TestClient:
    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Should work as async context manager."""
        async with Client(methods=[]) as client:
            assert client is not None

    @pytest.mark.asyncio
    async def test_get(self, httpx_mock: HTTPXMock) -> None:
        """Should send GET request."""
        httpx_mock.add_response(url="https://example.com/test", json={"ok": True})

        async with Client(methods=[]) as client:
            response = await client.get("https://example.com/test")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_post(self, httpx_mock: HTTPXMock) -> None:
        """Should send POST request."""
        httpx_mock.add_response(
            url="https://example.com/test", method="POST", json={"created": True}
        )

        async with Client(methods=[]) as client:
            response = await client.post("https://example.com/test")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_put(self, httpx_mock: HTTPXMock) -> None:
        """Should send PUT request."""
        httpx_mock.add_response(
            url="https://example.com/test", method="PUT", json={"updated": True}
        )

        async with Client(methods=[]) as client:
            response = await client.put("https://example.com/test")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_delete(self, httpx_mock: HTTPXMock) -> None:
        """Should send DELETE request."""
        httpx_mock.add_response(
            url="https://example.com/test", method="DELETE", json={"deleted": True}
        )

        async with Client(methods=[]) as client:
            response = await client.delete("https://example.com/test")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_on_delegates_to_transport(self) -> None:
        """Client should expose event registration helpers."""
        async with Client(methods=[]) as client:
            events: list[str] = []
            unsubscribe = client.on_payment_failed(lambda payload: events.append("failed"))

            assert callable(unsubscribe)

            assert callable(client.on_challenge_received(lambda payload: None))
            assert callable(client.on_credential_created(lambda payload: None))
            assert callable(client.on_payment_response(lambda payload: None))


class TestConvenienceFunctions:
    @pytest.mark.asyncio
    async def test_request_function(self, httpx_mock: HTTPXMock) -> None:
        """Should send request with automatic payment handling."""
        httpx_mock.add_response(url="https://example.com/test", json={"ok": True})

        response = await request("GET", "https://example.com/test", methods=[])
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_function(self, httpx_mock: HTTPXMock) -> None:
        """get() should send GET request."""
        httpx_mock.add_response(url="https://example.com/test", json={"ok": True})

        response = await get("https://example.com/test", methods=[])
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_post_function(self, httpx_mock: HTTPXMock) -> None:
        """post() should send POST request."""
        httpx_mock.add_response(url="https://example.com/test", method="POST", json={"ok": True})

        response = await post("https://example.com/test", methods=[])
        assert response.status_code == 200
