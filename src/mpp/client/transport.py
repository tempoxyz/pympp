"""Payment-aware HTTP transport and client.

Implements automatic 402 Payment Required handling by:
1. Sending the initial request
2. If 402, parsing the WWW-Authenticate challenge
3. Finding a matching method to create credentials
4. Retrying with the Authorization header
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
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
from mpp.runtime import (
    AsyncHttpResponseContext,
    Method,
    PaymentRuntime,
    _challenge_is_expired,
)

logger = logging.getLogger(__name__)
_REFETCHED = "mpp.response_hook_refetched"

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
        "protocol": "http",
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


def _copy_request(
    request: httpx.Request,
    *,
    headers: httpx.Headers | None = None,
    extensions: dict[str, Any] | None = None,
) -> httpx.Request:
    return httpx.Request(
        method=request.method,
        url=request.url,
        headers=request.headers if headers is None else headers,
        content=request.content,
        extensions=request.extensions if extensions is None else extensions,
    )


def _bind_response_request(response: httpx.Response, request: httpx.Request) -> None:
    try:
        _ = response.request
    except RuntimeError:
        response.request = request


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
            self._runtime = PaymentRuntime(methods or [], events=events, _async_inline=True)
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
        """Register a handler for successful payment-aware responses."""
        return self.on(PAYMENT_RESPONSE, handler)

    def on_payment_failed(self, handler: EventHandler) -> Unsubscribe:
        """Register a handler for failed automatic payment handling."""
        return self.on(PAYMENT_FAILED, handler)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Handle request, automatically retrying on 402 with credentials."""
        response = await self._inner.handle_async_request(request)
        return await self._handle_async_response(request, response)

    async def _handle_async_response(
        self,
        request: httpx.Request,
        response: httpx.Response,
    ) -> httpx.Response:
        """Handle an already-dispatched response, retrying a payable 402."""
        if response.status_code != 402:
            return response

        await response.aread()

        # A high-level send may have followed redirects before returning the
        # 402. Apply policy and retry against the request that was challenged.
        challenged_request = _challenged_request(response, request)
        if not self._runtime.allows_http_payment(challenged_request.url):
            return response

        challenges, parse_error = _payment_challenges(response)

        try:
            challenge, matched_method = self._runtime.match_challenge(
                challenges,
                prefer_method_order=False,
                allow_name_only=True,
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
                        request=challenged_request,
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
            await challenged_request.aread()
        except httpx.StreamConsumed as cause:
            error = PaymentError(
                "Streaming request bodies cannot be replayed after a payment challenge. "
                "Use a buffered body for paid requests."
            )
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
            raise error from cause

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

        retry_request = _copy_request(challenged_request, headers=headers)

        with self._runtime._paid_operation():
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

            _bind_response_request(payment_response, challenged_request)

            event_emitted = False

            async def emit_payment_response(event_response: httpx.Response) -> None:
                nonlocal event_emitted
                if event_emitted or not event_response.is_success:
                    return
                event_emitted = True
                _bind_response_request(event_response, challenged_request)
                await self._runtime.emit_event(
                    PAYMENT_RESPONSE,
                    {
                        "challenge": challenge,
                        "challenges": challenges,
                        "credential": credential,
                        "method": matched_method,
                        "request": challenged_request,
                        "response": event_response,
                        "protocol": "http",
                    },
                )

            async def create_credential(context: Any) -> Credential:
                return await self._runtime.create_credential(
                    challenge,
                    matched_method,
                    context=context,
                    event_payload={
                        "challenges": challenges,
                        "request": challenged_request,
                        "response": payment_response,
                        "protocol": "http",
                    },
                )

            async def send(request: httpx.Request) -> httpx.Response:
                if not self._runtime.allows_http_payment(request.url):
                    raise PaymentError("HTTP response hook request is outside allowed origins")
                for key, value in challenged_request.extensions.items():
                    request.extensions.setdefault(key, value)
                hook_response = await self._inner.handle_async_request(request)
                _bind_response_request(hook_response, request)
                return hook_response

            refetch: Callable[[], Awaitable[httpx.Response]] | None
            refetched_response: httpx.Response | None = None
            if not challenged_request.extensions.get(_REFETCHED):
                refetched = False

                async def do_refetch() -> httpx.Response:
                    nonlocal event_emitted, refetched, refetched_response
                    if refetched:
                        raise PaymentError("Payment response can only be refetched once")
                    refetched = True
                    await emit_payment_response(payment_response)
                    event_emitted = True
                    await payment_response.aclose()
                    extensions = dict(challenged_request.extensions)
                    extensions[_REFETCHED] = True
                    refetched_response = await self.handle_async_request(
                        _copy_request(challenged_request, extensions=extensions)
                    )
                    return refetched_response

                refetch = do_refetch
            else:
                refetch = None

            final_response: httpx.Response | None = None
            try:
                final_response = await self._runtime.handle_async_http_response(
                    matched_method,
                    AsyncHttpResponseContext(
                        challenge=challenge,
                        credential=credential,
                        request=challenged_request,
                        response=payment_response,
                        send=send,
                        refetch=refetch,
                        create_credential=create_credential,
                        run_async=self._runtime.run_async,
                    ),
                )
                await emit_payment_response(final_response)
            except BaseException as error:
                closed: set[int] = set()
                for candidate in (final_response, refetched_response, payment_response):
                    if candidate is not None and id(candidate) not in closed:
                        closed.add(id(candidate))
                        await candidate.aclose()
                if isinstance(error, Exception):
                    await self._runtime.emit_event(
                        PAYMENT_FAILED,
                        _client_payment_failed_payload(
                            challenge=challenge,
                            challenges=challenges,
                            credential=credential,
                            error=error,
                            method=matched_method,
                            request=challenged_request,
                            response=payment_response,
                        ),
                    )
                raise

            assert final_response is not None
            _bind_response_request(final_response, challenged_request)
            return final_response

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
        """Register a handler for successful payment-aware responses."""
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
