"""Tests for client-side transport."""

import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

from mpp import Challenge, Credential, PaymentOutcomeUnknownError
from mpp.client import Client, PaymentTransport, get, post, request
from mpp.events import EventDispatcher
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


class TestPaymentTransport:
    def test_runtime_configuration_is_unambiguous(self) -> None:
        class FalseyRuntime(PaymentRuntime):
            def __bool__(self) -> bool:
                return False

        runtime = FalseyRuntime()

        with pytest.raises(TypeError, match="exactly one"):
            PaymentTransport()
        with pytest.raises(TypeError, match="exactly one"):
            PaymentTransport([], runtime=runtime)
        with pytest.raises(TypeError, match="events belongs"):
            PaymentTransport(runtime=runtime, events=EventDispatcher())
        assert PaymentTransport(runtime=runtime)._runtime is runtime

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

        inner = MockTransport(
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

        inner = MockTransport(
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

        inner = MockTransport(
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
        initial_body = inner.requests[0].content
        retry_body = inner.requests[1].content
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
    async def test_paid_retry_raises_for_streaming_body(self) -> None:
        """Should raise after a 402 for an async generator body.

        Streaming bodies cannot be reliably buffered and replayed: the generator
        may be infinite, already partially consumed, or tied to a one-shot source.
        A descriptive error is better than a silent empty body on the paid retry.
        """
        from mpp.errors import PaymentError

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
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        async def async_body_gen():
            yield b"chunk1"
            yield b"chunk2"

        request = httpx.Request("POST", "https://example.com", content=async_body_gen())
        with pytest.raises(PaymentError, match="Streaming request bodies"):
            await transport.handle_async_request(request)

        assert len(inner.requests) == 1

    @pytest.mark.asyncio
    async def test_streaming_body_passes_through_non_402(self) -> None:
        inner = MockTransport([httpx.Response(200)])
        transport = PaymentTransport(methods=[], inner=inner)

        async def body():
            yield b"one-shot"

        response = await transport.handle_async_request(
            httpx.Request("POST", "https://example.com", content=body())
        )

        assert response.status_code == 200
        assert len(inner.requests) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "www_authenticate",
        [
            None,
            "Bearer realm=test",
            Challenge(
                id="test-id",
                method="stripe",
                intent="charge",
                request={"amount": "1000"},
            ).to_www_authenticate("example.com"),
        ],
    )
    async def test_streaming_body_returns_unmatched_402(self, www_authenticate: str | None) -> None:
        headers = {"www-authenticate": www_authenticate} if www_authenticate else {}
        inner = MockTransport([httpx.Response(402, headers=headers, content=b"unmatched")])
        transport = PaymentTransport(methods=[MockMethod()], inner=inner)

        async def body():
            yield b"one-shot"

        response = await transport.handle_async_request(
            httpx.Request("POST", "https://example.com", content=body())
        )

        assert response.status_code == 402
        assert response.content == b"unmatched"
        assert len(inner.requests) == 1

    @pytest.mark.asyncio
    async def test_closes_challenge_response_when_read_fails(self) -> None:
        class FailingStream(httpx.AsyncByteStream):
            closed = False

            async def __aiter__(self):
                raise RuntimeError("read failed")
                yield b""  # pragma: no cover

            async def aclose(self) -> None:
                self.closed = True

        stream = FailingStream()
        transport = PaymentTransport(
            methods=[MockMethod()],
            inner=MockTransport([httpx.Response(402, stream=stream)]),
        )

        with pytest.raises(RuntimeError, match="read failed"):
            await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert stream.closed

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
    @pytest.mark.parametrize(
        "expires",
        ["2020-01-01T00:00:00Z", "2020-01-01T00:00:00", "not-a-date"],
    )
    async def test_skips_invalid_or_expired_challenge(self, expires: str) -> None:
        """Should return 402 without paying if challenge expiry is unsafe."""
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires=expires,
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
    async def test_handles_merged_www_authenticate_challenges(self) -> None:
        first = Challenge(
            id="first",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            description='one "two", three',
        )
        second = Challenge(
            id="second",
            method="stripe",
            intent="charge",
            request={"amount": "1000"},
        )
        header = ", ".join(
            [
                'Bearer realm="example"',
                first.to_www_authenticate("example.com"),
                'Basic realm="other"',
                second.to_www_authenticate("example.com"),
            ]
        )
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": header}),
                httpx.Response(200),
            ]
        )
        method = MockMethod()
        transport = PaymentTransport(methods=[method], inner=inner)
        received: list[Challenge] = []
        transport.on_challenge_received(lambda payload: received.extend(payload["challenges"]))

        response = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert response.status_code == 200
        assert [(item.id, item.description) for item in received] == [
            ("first", 'one "two", three'),
            ("second", None),
        ]
        assert method.create_credential.call_args.args[0].id == "first"

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
        assert raised.value.challenge.id == challenge.id
        assert raised.value.credential is not None
        assert raised.value.request.url == httpx.URL("https://example.com")
        assert events == ["failed:test-id:PaymentOutcomeUnknownError"]

    @pytest.mark.asyncio
    async def test_cancelled_paid_retry_has_unknown_outcome(self) -> None:
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        retry_started = asyncio.Event()

        class CancelledRetryTransport(MockTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.requests.append(request)
                if len(self.requests) == 1:
                    return httpx.Response(
                        402,
                        headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
                    )
                retry_started.set()
                await asyncio.Event().wait()
                raise AssertionError("unreachable")

        transport = PaymentTransport(
            methods=[MockMethod()],
            inner=CancelledRetryTransport([]),
        )
        failed: list[Exception] = []
        transport.on_payment_failed(lambda payload: failed.append(payload["error"]))
        task = asyncio.create_task(
            transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        )
        await retry_started.wait()
        task.cancel()

        with pytest.raises(PaymentOutcomeUnknownError) as raised:
            await task
        assert isinstance(raised.value.__cause__, asyncio.CancelledError)
        assert failed == [raised.value]
        assert not task.cancelled()

    @pytest.mark.asyncio
    async def test_does_not_pay_again_after_repeated_402(self) -> None:
        challenge = Challenge(
            id="test-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        required = httpx.Response(
            402,
            headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
        )
        inner = MockTransport([required, required])
        method = MockMethod()
        transport = PaymentTransport(methods=[method], inner=inner)

        response = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert response.status_code == 402
        assert len(inner.requests) == 2
        method.create_credential.assert_awaited_once()


class TestClient:
    @pytest.mark.asyncio
    async def test_uses_shared_runtime(self, httpx_mock: HTTPXMock) -> None:
        challenge = Challenge(
            id="shared",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
        )
        httpx_mock.add_response(
            status_code=402,
            headers={"www-authenticate": challenge.to_www_authenticate("example.com")},
        )
        httpx_mock.add_response(status_code=200)
        runtime = PaymentRuntime([MockMethod()])

        async with Client(runtime=runtime) as client:
            response = await client.get("https://example.com")

        assert response.status_code == 200

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
