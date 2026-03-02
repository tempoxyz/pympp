"""Tests for client-side transport."""

from unittest.mock import AsyncMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

from mpp import Challenge
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
    async def test_returns_402_when_no_matching_method(self) -> None:
        """Should return 402 when no matching method found."""
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

        request = httpx.Request("GET", "https://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 402
        assert len(inner.requests) == 1

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
    async def test_rejects_http_url(self) -> None:
        """Should refuse to send Payment credentials over plain HTTP."""
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
            ]
        )

        method = MockMethod()
        transport = PaymentTransport(methods=[method], inner=inner)

        request = httpx.Request("GET", "http://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 402
        assert len(inner.requests) == 1
        method.create_credential.assert_not_called()

    @pytest.mark.asyncio
    async def test_allows_http_when_allow_insecure(self) -> None:
        """Should send Payment credentials over HTTP when allow_insecure=True."""
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
        transport = PaymentTransport(methods=[method], inner=inner, allow_insecure=True)

        request = httpx.Request("GET", "http://example.com")
        response = await transport.handle_async_request(request)

        assert response.status_code == 200
        assert len(inner.requests) == 2
        method.create_credential.assert_called_once()

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
