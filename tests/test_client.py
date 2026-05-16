"""Tests for client-side transport."""

from unittest.mock import AsyncMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

from mpp import Challenge, Credential
from mpp.client import Client, PaymentTransport, get, post, request
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

        with pytest.raises(RuntimeError, match="network failed"):
            await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert events == ["failed:test-id:RuntimeError"]


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
