"""Synchronous payment-aware httpx transport."""

from __future__ import annotations

import logging
from collections.abc import Callable
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
from mpp.runtime import (
    Method,
    PaymentRuntime,
    SyncHttpResponseContext,
    _challenge_is_expired,
)

from .transport import (
    _REFETCHED,
    _bind_response_request,
    _challenged_request,
    _client_payment_failed_payload,
    _copy_request,
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
        response = self._inner.handle_request(request)
        return self._handle_response(request, response)

    def _handle_response(
        self,
        request: httpx.Request,
        response: httpx.Response,
    ) -> httpx.Response:
        """Handle an already-dispatched response, retrying a payable 402."""
        if response.status_code != 402:
            return response

        response.read()
        challenged_request = _challenged_request(response, request)
        if not self._runtime.allows_http_payment(challenged_request.url):
            return response

        challenges, parse_error = _payment_challenges(response)
        try:
            challenge, method = self._runtime.match_challenge(
                challenges,
                prefer_method_order=False,
                allow_name_only=True,
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
            challenged_request.read()
        except httpx.StreamConsumed as cause:
            error = PaymentError(
                "Streaming request bodies cannot be replayed after a payment challenge. "
                "Use a buffered body for paid requests."
            )
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
            raise error from cause

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
            auth_header = credential.to_authorization()
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
        headers["Authorization"] = auth_header
        retry_request = _copy_request(challenged_request, headers=headers)

        with self._runtime._paid_operation():
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

            _bind_response_request(payment_response, challenged_request)

            event_emitted = False

            def emit_payment_response(event_response: httpx.Response) -> None:
                nonlocal event_emitted
                if event_emitted or not event_response.is_success:
                    return
                event_emitted = True
                _bind_response_request(event_response, challenged_request)
                self._runtime.emit_event_sync(
                    PAYMENT_RESPONSE,
                    {
                        "challenge": challenge,
                        "challenges": challenges,
                        "credential": credential,
                        "method": method,
                        "request": challenged_request,
                        "response": event_response,
                        "protocol": "http",
                    },
                )

            def create_credential(context: object):
                return self._runtime.create_credential_sync(
                    challenge,
                    method,
                    context=context,
                    event_payload={
                        "challenges": challenges,
                        "request": challenged_request,
                        "response": payment_response,
                        "protocol": "http",
                    },
                )

            def send(request: httpx.Request) -> httpx.Response:
                if not self._runtime.allows_http_payment(request.url):
                    raise PaymentError("HTTP response hook request is outside allowed origins")
                for key, value in challenged_request.extensions.items():
                    request.extensions.setdefault(key, value)
                hook_response = self._inner.handle_request(request)
                _bind_response_request(hook_response, request)
                return hook_response

            refetch: Callable[[], httpx.Response] | None
            refetched_response: httpx.Response | None = None
            if not challenged_request.extensions.get(_REFETCHED):
                refetched = False

                def do_refetch() -> httpx.Response:
                    nonlocal event_emitted, refetched, refetched_response
                    if refetched:
                        raise PaymentError("Payment response can only be refetched once")
                    refetched = True
                    emit_payment_response(payment_response)
                    event_emitted = True
                    payment_response.close()
                    extensions = dict(challenged_request.extensions)
                    extensions[_REFETCHED] = True
                    refetched_response = self.handle_request(
                        _copy_request(challenged_request, extensions=extensions)
                    )
                    return refetched_response

                refetch = do_refetch
            else:
                refetch = None

            final_response: httpx.Response | None = None
            try:
                final_response = self._runtime.handle_http_response(
                    method,
                    SyncHttpResponseContext(
                        challenge=challenge,
                        credential=credential,
                        request=challenged_request,
                        response=payment_response,
                        send=send,
                        refetch=refetch,
                        create_credential=create_credential,
                        run_sync=self._runtime.run_sync,
                    ),
                )
                emit_payment_response(final_response)
            except BaseException as error:
                closed: set[int] = set()
                for candidate in (final_response, refetched_response, payment_response):
                    if candidate is not None and id(candidate) not in closed:
                        closed.add(id(candidate))
                        candidate.close()
                if isinstance(error, Exception):
                    self._runtime.emit_event_sync(
                        PAYMENT_FAILED,
                        _client_payment_failed_payload(
                            challenge=challenge,
                            challenges=challenges,
                            credential=credential,
                            error=error,
                            method=method,
                            request=challenged_request,
                            response=payment_response,
                        ),
                    )
                raise

            assert final_response is not None
            _bind_response_request(final_response, challenged_request)
            return final_response

    def close(self) -> None:
        """Close the inner transport."""
        try:
            self._inner.close()
        finally:
            if self._owns_runtime:
                self._runtime.close()
