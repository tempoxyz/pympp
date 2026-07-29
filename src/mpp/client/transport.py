"""Payment-aware HTTP transport and client.

Implements automatic 402 Payment Required handling by:
1. Sending the initial request
2. If 402, parsing the WWW-Authenticate challenge
3. Finding a matching method to create credentials
4. Retrying with the Authorization header
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from mpp.client._http import (
    _PAYMENT_SENT,
    _challenge_is_expired,
    _close_response,
    _failed_payload,
    _HttpPayment,
    _match_http_challenge,
    _payment_challenges,
    _propagate_response_cookies,
    _response_request,
)
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
from mpp.events import (
    CHALLENGE_RECEIVED,
    CREDENTIAL_CREATED,
    PAYMENT_FAILED,
    PAYMENT_RESPONSE,
    EventDispatcher,
    EventHandler,
    Unsubscribe,
)
from mpp.runtime import Method, PaymentRuntime

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Sequence


class _EventHandlers:
    _events: EventDispatcher

    def on(self, name: str, handler: EventHandler) -> Unsubscribe:
        """Register a client payment event handler."""
        return self._events.on(name, handler)

    def on_challenge_received(self, handler: EventHandler) -> Unsubscribe:
        return self.on(CHALLENGE_RECEIVED, handler)

    def on_credential_created(self, handler: EventHandler) -> Unsubscribe:
        return self.on(CREDENTIAL_CREATED, handler)

    def on_payment_response(self, handler: EventHandler) -> Unsubscribe:
        return self.on(PAYMENT_RESPONSE, handler)

    def on_payment_failed(self, handler: EventHandler) -> Unsubscribe:
        return self.on(PAYMENT_FAILED, handler)


class PaymentTransport(_EventHandlers, httpx.AsyncBaseTransport):
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
            self._runtime = PaymentRuntime(methods, events=events)
        self._inner = inner or httpx.AsyncHTTPTransport()
        self._events = self._runtime.events

    async def _fail(self, payment: _HttpPayment, error: Exception, **details: Any) -> None:
        await self._runtime.emit_event(PAYMENT_FAILED, payment.failed(error, **details))

    async def _unknown(
        self,
        payment: _HttpPayment,
        cause: BaseException,
        response: httpx.Response | None = None,
    ) -> PaymentOutcomeUnknownError:
        error = payment.unknown(cause)
        await self._fail(payment, error, response=response)
        return error

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Handle request, automatically retrying on 402 with credentials."""
        if not (
            isinstance(request.stream, httpx.AsyncByteStream)
            and not isinstance(request.stream, httpx.SyncByteStream)
        ):
            await request.aread()
        response = await self._inner.handle_async_request(request)
        if response.status_code != 402:
            return response
        request = _response_request(response, request)
        if not self._runtime.allows_http_payment(request.url):
            return response
        payment_source = request.extensions.get(_PAYMENT_SENT)
        if isinstance(payment_source, int) and payment_source != id(request):
            return response

        challenges, parse_error = _payment_challenges(response)
        challenge = method = None
        if challenges:
            try:
                self._runtime.start()
                challenge, method = _match_http_challenge(self._runtime, challenges)
            except BaseException:
                await _close_response(response)
                raise
        if challenge is None or method is None:
            if parse_error is not None or challenges:
                try:
                    await self._runtime.emit_event(
                        PAYMENT_FAILED,
                        _failed_payload(
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
                except BaseException:
                    await _close_response(response)
                    raise
            return response

        payment = _HttpPayment(challenges, challenge, method, request, response)
        if _challenge_is_expired(challenge):
            logger.warning("Challenge expired at %s, not paying", challenge.expires)
            try:
                await self._fail(payment, ValueError(f"Challenge expired at {challenge.expires}"))
            except BaseException:
                await _close_response(response)
                raise
            return response

        try:
            await request.aread()
        except httpx.StreamConsumed as cause:
            error = PaymentError(
                "Streaming request bodies cannot be replayed after a payment challenge. "
                "Use a buffered body for paid requests."
            )
            try:
                await self._fail(payment, error)
            finally:
                await _close_response(response)
            raise error from cause
        except BaseException:
            await _close_response(response)
            raise

        try:
            await response.aread()
            await response.aclose()
        except BaseException:
            await _close_response(response)
            raise

        with self._runtime._paid_operation():
            try:
                attempt = self._runtime._begin_http_payment(challenge, request)
            except PaymentOutcomeUnknownError as error:
                await self._fail(payment, error)
                raise

            try:
                credential = await self._runtime.create_credential(
                    challenge,
                    method,
                    event_payload=payment.event_payload(),
                )
                authorization = credential.to_authorization()
                payment.credential = credential
                attempt.credential = credential
                retry_request = payment.retry_request(authorization)
            except BaseException as error:
                attempt.discard()
                if isinstance(error, Exception):
                    await self._fail(payment, error)
                raise

            try:
                attempt.mark_sent(retry_request)
                payment_response = await self._inner.handle_async_request(retry_request)
            except BaseException as cause:
                if not attempt.sent:
                    attempt.discard()
                    if isinstance(cause, Exception):
                        await self._fail(payment, cause)
                    raise
                outcome = attempt.unknown(cause)
                if not isinstance(cause, Exception):
                    raise
                error = await self._unknown(payment, outcome.cause)
                raise error from cause

            try:
                if payment_response.status_code == 402:
                    cause = RuntimeError(
                        "Server returned another payment challenge after receiving a credential"
                    )
                    attempt.unknown(cause)
                    error = await self._unknown(payment, cause, response=payment_response)
                    raise error from cause

                if payment_response.status_code >= 400:
                    cause = RuntimeError(
                        f"Credentialed request returned HTTP {payment_response.status_code}"
                    )
                    attempt.unknown(cause)
                    await self._unknown(payment, cause, response=payment_response)
                else:
                    attempt.complete()

                _response_request(payment_response, retry_request)
                _propagate_response_cookies(response, payment_response)
                if payment_response.is_success:
                    await self._runtime.emit_event(
                        PAYMENT_RESPONSE,
                        payment.event_payload(payment_response),
                    )
                return payment_response
            except BaseException as error:
                if attempt.sent and not attempt.completed and attempt.unknown_outcome is None:
                    attempt.unknown(error)
                await _close_response(payment_response)
                raise

    async def aclose(self) -> None:
        """Close the inner transport and an implicitly created runtime."""
        try:
            await self._inner.aclose()
        finally:
            if self._owns_runtime:
                await self._runtime.aclose()


class Client(_EventHandlers):
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
        self._events = self._transport._events

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
