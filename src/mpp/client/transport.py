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
from typing import TYPE_CHECKING, Any

import httpx

from mpp import Challenge, Credential
from mpp._parsing import ParseError
from mpp.errors import PaymentError
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

logger = logging.getLogger(__name__)

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


def _challenged_request(
    response: httpx.Response,
    fallback: httpx.Request,
) -> httpx.Request:
    try:
        return response.request
    except RuntimeError:
        return fallback


def _payment_challenges(response: httpx.Response) -> tuple[list[Challenge], ParseError | None]:
    challenges: list[Challenge] = []
    parse_error: ParseError | None = None
    for header in response.headers.get_list("www-authenticate"):
        if not header.lower().startswith("payment "):
            continue
        try:
            challenges.append(Challenge.from_www_authenticate(header))
        except ParseError as error:
            parse_error = error
    return challenges, parse_error


def _challenge_is_expired(challenge: Challenge) -> bool:
    if not challenge.expires:
        return False
    try:
        expires = datetime.fromisoformat(challenge.expires.replace("Z", "+00:00"))
    except ValueError:
        return False
    return expires < datetime.now(UTC)


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
        self._owns_runtime = runtime is None
        if runtime is not None:
            if methods is not None or events is not None:
                raise ValueError("Pass either methods/events or runtime, not both")
            self._runtime = runtime
        else:
            if methods is None:
                raise ValueError("Pass methods or runtime")
            self._runtime = PaymentRuntime(methods or [], events=events)
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
        # Async-generator bodies (content=async_gen()) produce an AsyncByteStream
        # that is not also a SyncByteStream. They cannot be safely buffered for
        # replay: the generator may be infinite, already partially consumed, or
        # tied to a one-shot I/O source. Reject early so callers get a clear
        # message instead of a silent empty body on the paid retry.
        if isinstance(request.stream, httpx.AsyncByteStream) and not isinstance(
            request.stream, httpx.SyncByteStream
        ):
            raise PaymentError(
                "Streaming request bodies (async generators) are not supported "
                "through the payment retry flow. Use a buffered body "
                "(bytes, str, files=, or data=) instead."
            )

        # Buffer the request body before the first dispatch so it can be replayed
        # on a paid 402 retry. Handles bytes bodies and multipart/files= bodies.
        # After aread() the stream is replaced with a replayable ByteStream.
        await request.aread()

        response = await self._inner.handle_async_request(request)

        if response.status_code != 402:
            return response

        await response.aread()

        # A high-level send may have followed redirects before returning the
        # 402. Apply policy and retry against the request that was challenged.
        challenged_request = _challenged_request(response, request)
        if not self._runtime.allows_http_payment(challenged_request.url):
            return response
        await challenged_request.aread()

        challenges, parse_error = _payment_challenges(response)

        try:
            challenge, matched_method = self._runtime.match_challenge(
                challenges,
                prefer_method_order=False,
            )
        except ValueError:
            challenge = None
            matched_method = None

        if not challenge or not matched_method:
            if parse_error is not None or challenges:
                # Surface parse/method-selection failures to observers while
                # preserving the original 402 response for the caller.
                await self._runtime.emit_event(
                    PAYMENT_FAILED,
                    _client_payment_failed_payload(
                        challenge=None,
                        challenges=challenges,
                        credential=None,
                        error=parse_error
                        or ValueError("No compatible payment method for challenges"),
                        method=None,
                        request=request,
                        response=response,
                    ),
                )
            return response

        # Check expiry before paying (client-side guardrail)
        if _challenge_is_expired(challenge):
            logger.warning("Challenge expired at %s, not paying", challenge.expires)
            await self._runtime.emit_event(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=None,
                    error=ValueError(f"Challenge expired at {challenge.expires}"),
                    method=matched_method,
                    request=challenged_request,
                    response=response,
                ),
            )
            return response

        try:
            credential = await self._runtime.create_credential(
                challenge,
                matched_method,
                event_payload={
                    "challenges": challenges,
                    "request": challenged_request,
                    "response": response,
                    "protocol": "http",
                },
            )
            auth_header = credential.to_authorization()
        except Exception as error:
            await self._runtime.emit_event(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=None,
                    error=error,
                    method=matched_method,
                    request=challenged_request,
                    response=response,
                ),
            )
            raise

        headers = httpx.Headers(challenged_request.headers)
        headers["Authorization"] = auth_header

        retry_request = httpx.Request(
            method=challenged_request.method,
            url=challenged_request.url,
            headers=headers,
            content=challenged_request.content,
            extensions=challenged_request.extensions,
        )

        try:
            payment_response = await self._inner.handle_async_request(retry_request)
        except Exception as error:
            await self._runtime.emit_event(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=credential,
                    error=error,
                    method=matched_method,
                    request=challenged_request,
                    response=response,
                ),
            )
            raise

        if payment_response.is_success:
            await self._runtime.emit_event(
                PAYMENT_RESPONSE,
                {
                    "challenge": challenge,
                    "credential": credential,
                    "method": matched_method,
                    "request": challenged_request,
                    "response": payment_response,
                    "protocol": "http",
                },
            )

        return payment_response

    async def aclose(self) -> None:
        """Close the inner transport."""
        try:
            await self._inner.aclose()
        finally:
            if self._owns_runtime:
                await self._runtime.aclose()


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
        self._transport = PaymentTransport(methods=methods, runtime=runtime)
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
    methods: Sequence[Method] | None = None,
    runtime: PaymentRuntime | None = None,
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
    async with Client(methods, runtime=runtime) as client:
        return await client.request(method, url, **kwargs)


async def get(
    url: str,
    *,
    methods: Sequence[Method] | None = None,
    runtime: PaymentRuntime | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Send a GET request with automatic payment handling."""
    return await request("GET", url, methods=methods, runtime=runtime, **kwargs)


async def post(
    url: str,
    *,
    methods: Sequence[Method] | None = None,
    runtime: PaymentRuntime | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Send a POST request with automatic payment handling."""
    return await request("POST", url, methods=methods, runtime=runtime, **kwargs)
