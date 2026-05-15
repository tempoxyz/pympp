"""Payment-aware HTTP transport and client.

Implements automatic 402 Payment Required handling by:
1. Sending the initial request
2. If 402, parsing the WWW-Authenticate challenge
3. Finding a matching method to create credentials
4. Retrying with the Authorization header
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import httpx

from mpp import Challenge, Credential
from mpp._parsing import ParseError
from mpp.events import EventDispatcher, EventHandler, Unsubscribe

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Sequence


@runtime_checkable
class Method(Protocol):
    """Payment method interface for client-side credential creation."""

    name: str

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge."""
        ...


class PaymentTransport(httpx.AsyncBaseTransport):
    """httpx transport that handles 402 Payment Required responses.

    Wraps an inner transport and automatically:
    1. Detects 402 responses with WWW-Authenticate: Payment headers
    2. Parses the challenge and finds a matching payment method
    3. Creates credentials and retries the request
    4. Returns the final response (success or failure)

    Example:
        transport = PaymentTransport(
            methods=[tempo(...)],
            inner=httpx.AsyncHTTPTransport(),
        )

        async with httpx.AsyncClient(transport=transport) as client:
            response = await client.get("https://api.example.com/resource")
    """

    def __init__(
        self,
        methods: Sequence[Method],
        inner: httpx.AsyncBaseTransport | None = None,
        events: EventDispatcher | None = None,
    ) -> None:
        self._methods = {m.name: m for m in methods}
        self._inner = inner or httpx.AsyncHTTPTransport()
        self._events = events or EventDispatcher()

    def on(self, name: str, handler: EventHandler) -> Unsubscribe:
        """Register a client payment event handler."""
        return self._events.on(name, handler)

    def on_challenge_received(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for selected payment challenges."""
        return self.on("challenge.received", handler)

    def on_credential_created(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for created credentials."""
        return self.on("credential.created", handler)

    def on_payment_response(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for successful paid retry responses."""
        return self.on("payment.response", handler)

    def on_payment_failed(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for failed automatic payment handling."""
        return self.on("payment.failed", handler)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Handle request, automatically retrying on 402 with credentials."""
        response = await self._inner.handle_async_request(request)

        if response.status_code != 402:
            return response

        await response.aread()

        # Handle multiple WWW-Authenticate headers (per RFC 9110)
        www_auth_headers = response.headers.get_list("www-authenticate")

        challenges: list[Challenge] = []
        parse_error: ParseError | None = None
        for header in www_auth_headers:
            if not header.lower().startswith("payment "):
                continue
            try:
                parsed = Challenge.from_www_authenticate(header)
            except ParseError as error:
                parse_error = error
                continue
            challenges.append(parsed)

        challenge = None
        matched_method = None
        for parsed in challenges:
            if parsed.method in self._methods:
                challenge = parsed
                matched_method = self._methods[parsed.method]
                break

        if not challenge or not matched_method:
            if parse_error is not None or challenges:
                await self._events.emit(
                    "payment.failed",
                    {
                        "challenges": challenges or None,
                        "error": parse_error
                        or ValueError("No compatible payment method for challenges"),
                        "request": request,
                        "response": response,
                    },
                )
            return response

        # Check expiry before paying (client-side guardrail)
        if challenge.expires:
            try:
                expires_dt = datetime.fromisoformat(challenge.expires.replace("Z", "+00:00"))
                if expires_dt < datetime.now(UTC):
                    logger.warning("Challenge expired at %s, not paying", challenge.expires)
                    await self._events.emit(
                        "payment.failed",
                        {
                            "challenge": challenge,
                            "challenges": challenges,
                            "error": ValueError(f"Challenge expired at {challenge.expires}"),
                            "method": matched_method,
                            "request": request,
                            "response": response,
                        },
                    )
                    return response
            except ValueError:
                pass  # If we can't parse, let server validate

        try:
            event_credential = await self._events.emit(
                "challenge.received",
                {
                    "challenge": challenge,
                    "challenges": challenges,
                    "method": matched_method,
                    "request": request,
                    "response": response,
                },
            )
            credential = (
                event_credential
                if isinstance(event_credential, Credential)
                else await matched_method.create_credential(challenge)
            )
            await self._events.emit(
                "credential.created",
                {
                    "challenge": challenge,
                    "credential": credential,
                    "method": matched_method,
                    "request": request,
                    "response": response,
                },
            )
            auth_header = credential.to_authorization()
        except Exception as error:
            await self._events.emit(
                "payment.failed",
                {
                    "challenge": challenge,
                    "challenges": challenges,
                    "error": error,
                    "method": matched_method,
                    "request": request,
                    "response": response,
                },
            )
            raise

        headers = httpx.Headers(request.headers)
        headers["Authorization"] = auth_header

        retry_request = httpx.Request(
            method=request.method,
            url=request.url,
            headers=headers,
            stream=request.stream,
            extensions=request.extensions,
        )

        try:
            payment_response = await self._inner.handle_async_request(retry_request)
        except Exception as error:
            await self._events.emit(
                "payment.failed",
                {
                    "challenge": challenge,
                    "challenges": challenges,
                    "credential": credential,
                    "error": error,
                    "method": matched_method,
                    "request": request,
                    "response": response,
                },
            )
            raise

        if payment_response.is_success:
            await self._events.emit(
                "payment.response",
                {
                    "challenge": challenge,
                    "credential": credential,
                    "method": matched_method,
                    "request": request,
                    "response": payment_response,
                },
            )

        return payment_response

    async def aclose(self) -> None:
        """Close the inner transport."""
        await self._inner.aclose()


class Client:
    """HTTP client with automatic payment handling.

    Example:
        async with Client(methods=[tempo(...)]) as client:
            response = await client.get("https://api.example.com/resource")
    """

    def __init__(self, methods: Sequence[Method]) -> None:
        self._transport = PaymentTransport(methods)
        self._client = httpx.AsyncClient(transport=self._transport)

    def on(self, name: str, handler: EventHandler) -> Unsubscribe:
        """Register a client payment event handler."""
        return self._transport.on(name, handler)

    def on_challenge_received(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for selected payment challenges."""
        return self.on("challenge.received", handler)

    def on_credential_created(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for created credentials."""
        return self.on("credential.created", handler)

    def on_payment_response(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for successful paid retry responses."""
        return self.on("payment.response", handler)

    def on_payment_failed(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for failed automatic payment handling."""
        return self.on("payment.failed", handler)

    async def __aenter__(self) -> Client:
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.__aexit__(*args)

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send an HTTP request."""
        return await self._client.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send a DELETE request."""
        return await self.request("DELETE", url, **kwargs)


async def request(
    method: str,
    url: str,
    *,
    methods: Sequence[Method],
    **kwargs: Any,
) -> httpx.Response:
    """Send an HTTP request with automatic payment handling.

    This is a convenience function that creates a temporary client for a single request.
    For multiple requests, use Client for connection pooling.

    Example:
        response = await request(
            "GET",
            "https://api.example.com/resource",
            methods=[tempo(...)],
        )
    """
    async with Client(methods) as client:
        return await client.request(method, url, **kwargs)


async def get(url: str, *, methods: Sequence[Method], **kwargs: Any) -> httpx.Response:
    """Send a GET request with automatic payment handling."""
    return await request("GET", url, methods=methods, **kwargs)


async def post(url: str, *, methods: Sequence[Method], **kwargs: Any) -> httpx.Response:
    """Send a POST request with automatic payment handling."""
    return await request("POST", url, methods=methods, **kwargs)
