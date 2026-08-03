"""Payment-aware HTTP transport and client.

Implements automatic 402 Payment Required handling by:
1. Sending the initial request
2. If 402, parsing the WWW-Authenticate challenge
3. Finding a matching method to create credentials
4. Retrying with the Authorization header
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import TYPE_CHECKING, Any

import httpx

from mpp import Challenge, Credential
from mpp._parsing import ParseError
from mpp.errors import (
    InvalidChallengeError,
    PaymentError,
    PaymentExpiredError,
    PaymentOutcomeUnknownError,
)
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    PAYMENT_FAILED,
    PAYMENT_RESPONSE,
    ClientPaymentFailedPayload,
    EventDispatcher,
    EventHandler,
    Unsubscribe,
)
from mpp.runtime import Method, PaymentRuntime

if TYPE_CHECKING:
    from collections.abc import Sequence


def _client_payment_failed_payload(
    *,
    challenge: Challenge | None,
    challenges: list[Challenge],
    credential: Credential | None,
    error: Exception,
    method: Method | None,
    request: httpx.Request,
    response: httpx.Response,
) -> ClientPaymentFailedPayload:
    return {
        "challenge": challenge,
        "challenges": challenges,
        "credential": credential,
        "error": error,
        "method": method,
        "request": request,
        "response": response,
    }


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
        methods: Sequence[Method] | None = None,
        inner: httpx.AsyncBaseTransport | None = None,
        events: EventDispatcher | None = None,
        *,
        runtime: PaymentRuntime | None = None,
    ) -> None:
        if (methods is None) == (runtime is None):
            raise TypeError("Provide exactly one of methods or runtime")
        if runtime is not None and events is not None:
            raise TypeError("events belongs to the provided runtime")
        self._runtime = (
            runtime if runtime is not None else PaymentRuntime(methods or (), events=events)
        )
        self._inner = inner or httpx.AsyncHTTPTransport()
        self._events = self._runtime.events

    def on(self, name: str, handler: EventHandler) -> Unsubscribe:
        """Register a client payment event handler."""
        return self._events.on(name, handler)

    def on_challenge_received(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for selected payment challenges."""
        return self.on(CHALLENGE_RECEIVED, handler)

    def on_credential_created(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for created credentials."""
        return self.on(CREDENTIAL_CREATED, handler)

    def on_payment_response(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for successful paid retry responses."""
        return self.on(PAYMENT_RESPONSE, handler)

    def on_payment_failed(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for failed automatic payment handling."""
        return self.on(PAYMENT_FAILED, handler)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Handle request, automatically retrying on 402 with credentials."""
        replayable = not (
            isinstance(request.stream, httpx.AsyncByteStream)
            and not isinstance(request.stream, httpx.SyncByteStream)
        )
        if replayable:
            await request.aread()

        response = await self._inner.handle_async_request(request)

        if response.status_code != 402:
            return response

        try:
            await response.aread()
        except BaseException:
            with suppress(BaseException):
                await response.aclose()
            raise

        # Handle multiple WWW-Authenticate headers (per RFC 9110)
        challenges: list[Challenge] = []
        parse_error: ParseError | None = None
        for header in response.headers.get_list("www-authenticate"):
            for field in _payment_challenges(header):
                try:
                    parsed = Challenge.from_www_authenticate(field)
                except ParseError as error:
                    parse_error = error
                    continue
                challenges.append(parsed)

        try:
            challenge, matched_method = self._runtime.match_challenge(challenges)
        except ValueError as match_error:
            if parse_error is not None or challenges:
                # Surface parse/method-selection failures to observers while
                # preserving the original 402 response for the caller.
                await self._events.emit(
                    PAYMENT_FAILED,
                    _client_payment_failed_payload(
                        challenge=None,
                        challenges=challenges,
                        credential=None,
                        error=parse_error or match_error,
                        method=None,
                        request=request,
                        response=response,
                    ),
                )
            return response

        if not replayable:
            await response.aclose()
            raise PaymentError(
                "Streaming request bodies cannot be replayed after a payment challenge. "
                "Use a buffered body for paid requests."
            )

        try:
            credential = await self._runtime.create_credential(
                challenge,
                matched_method,
                event_payload={
                    "challenges": challenges,
                    "request": request,
                    "response": response,
                },
            )
            auth_header = credential.to_authorization()
        except Exception as error:
            await self._events.emit(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=None,
                    error=error,
                    method=matched_method,
                    request=request,
                    response=response,
                ),
            )
            if isinstance(error, (InvalidChallengeError, PaymentExpiredError)):
                return response
            raise

        headers = httpx.Headers(request.headers)
        headers["Authorization"] = auth_header

        retry_request = httpx.Request(
            method=request.method,
            url=request.url,
            headers=headers,
            content=request.content,
            extensions=request.extensions,
        )

        try:
            payment_response = await self._inner.handle_async_request(retry_request)
        except (Exception, asyncio.CancelledError) as cause:
            error = PaymentOutcomeUnknownError(
                challenge,
                cause,
                credential=credential,
                request=request,
            )
            await self._events.emit(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=credential,
                    error=error,
                    method=matched_method,
                    request=request,
                    response=response,
                ),
            )
            raise error from cause

        if payment_response.is_success:
            await self._events.emit(
                PAYMENT_RESPONSE,
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

    def __init__(
        self,
        methods: Sequence[Method] | None = None,
        *,
        runtime: PaymentRuntime | None = None,
    ) -> None:
        self._transport = PaymentTransport(methods, runtime=runtime)
        self._client = httpx.AsyncClient(transport=self._transport)

    def on(self, name: str, handler: EventHandler) -> Unsubscribe:
        """Register a client payment event handler."""
        return self._transport.on(name, handler)

    def on_challenge_received(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for selected payment challenges."""
        return self.on(CHALLENGE_RECEIVED, handler)

    def on_credential_created(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for created credentials."""
        return self.on(CREDENTIAL_CREATED, handler)

    def on_payment_response(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for successful paid retry responses."""
        return self.on(PAYMENT_RESPONSE, handler)

    def on_payment_failed(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for failed automatic payment handling."""
        return self.on(PAYMENT_FAILED, handler)

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


def _payment_challenges(value: str) -> list[str]:
    """Return Payment challenges, preserving quoted commas and escapes."""
    fields: list[str] = []
    start = 0
    quoted = escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == "," and not quoted:
            fields.append(value[start:index])
            start = index + 1
    fields.append(value[start:])

    challenges: list[str] = []
    current: list[str] | None = None
    for field in map(str.strip, fields):
        scheme, _, remainder = field.partition(" ")
        if "=" not in scheme and not remainder.lstrip().startswith("="):
            if current:
                challenges.append(", ".join(current))
            current = [field] if scheme.lower() == "payment" else None
        elif current:
            current.append(field)
    if current:
        challenges.append(", ".join(current))
    return challenges
