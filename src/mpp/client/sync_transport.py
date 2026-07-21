"""Synchronous payment-aware httpx transport."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from mpp.errors import PaymentError
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

from .transport import (
    _challenge_is_expired,
    _challenged_request,
    _client_payment_failed_payload,
    _payment_challenges,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


class SyncPaymentTransport(httpx.BaseTransport):
    """httpx transport that synchronously handles 402 payment challenges."""

    def __init__(
        self,
        methods: Sequence[Method] | None = None,
        inner: httpx.BaseTransport | None = None,
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
        self._inner = inner or httpx.HTTPTransport()
        self._events = self._runtime.events

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

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Send a request and retry one 402 with a payment credential."""
        if isinstance(request.stream, httpx.SyncByteStream) and not isinstance(
            request.stream, httpx.AsyncByteStream
        ):
            raise PaymentError(
                "Streaming request bodies (generators) are not supported through the "
                "payment retry flow. Use a buffered body (bytes, str, files=, or data=) instead."
            )

        request.read()
        response = self._inner.handle_request(request)
        if response.status_code != 402:
            return response

        response.read()
        challenged_request = _challenged_request(response, request)
        if not self._runtime.allows_http_payment(challenged_request.url):
            return response
        challenged_request.read()

        challenges, parse_error = _payment_challenges(response)
        try:
            challenge, method = self._runtime.match_challenge(
                challenges,
                prefer_method_order=False,
            )
        except ValueError:
            challenge = None
            method = None

        if challenge is None or method is None:
            if parse_error is not None or challenges:
                self._runtime.emit_event_sync(
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

        if _challenge_is_expired(challenge):
            logger.warning("Challenge expired at %s, not paying", challenge.expires)
            self._runtime.emit_event_sync(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=None,
                    error=ValueError(f"Challenge expired at {challenge.expires}"),
                    method=method,
                    request=challenged_request,
                    response=response,
                ),
            )
            return response

        try:
            credential = self._runtime.create_credential_sync(
                challenge,
                method,
                event_payload={
                    "challenges": challenges,
                    "request": challenged_request,
                    "response": response,
                    "protocol": "http",
                },
            )
        except Exception as error:
            self._runtime.emit_event_sync(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=None,
                    error=error,
                    method=method,
                    request=challenged_request,
                    response=response,
                ),
            )
            raise

        headers = httpx.Headers(challenged_request.headers)
        headers["Authorization"] = credential.to_authorization()
        retry_request = httpx.Request(
            method=challenged_request.method,
            url=challenged_request.url,
            headers=headers,
            content=challenged_request.content,
            extensions=challenged_request.extensions,
        )

        try:
            payment_response = self._inner.handle_request(retry_request)
        except Exception as error:
            self._runtime.emit_event_sync(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=credential,
                    error=error,
                    method=method,
                    request=challenged_request,
                    response=response,
                ),
            )
            raise

        if payment_response.is_success:
            self._runtime.emit_event_sync(
                PAYMENT_RESPONSE,
                {
                    "challenge": challenge,
                    "credential": credential,
                    "method": method,
                    "request": challenged_request,
                    "response": payment_response,
                    "protocol": "http",
                },
            )
        return payment_response

    def close(self) -> None:
        """Close the inner transport."""
        try:
            self._inner.close()
        finally:
            if self._owns_runtime:
                self._runtime.close()
