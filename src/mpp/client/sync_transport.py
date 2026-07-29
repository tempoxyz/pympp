"""Synchronous payment-aware HTTPX transport."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from mpp.client._http import (
    _PAYMENT_SENT,
    _challenge_is_expired,
    _failed_payload,
    _HttpPayment,
    _match_http_challenge,
    _payment_challenges,
    _propagate_response_cookies,
    _response_request,
    _settle_http_payment,
)
from mpp.client.transport import _EventHandlers
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
from mpp.events import PAYMENT_FAILED, PAYMENT_RESPONSE, EventDispatcher
from mpp.runtime import Method, OwnedPaymentRuntime

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


def _close_response(response: httpx.Response) -> None:
    try:
        response.close()
    except BaseException:
        pass


class SyncPaymentTransport(_EventHandlers, httpx.BaseTransport):
    """HTTPX transport that synchronously handles one payment challenge."""

    def __init__(
        self,
        methods: Sequence[Method] | None = None,
        inner: httpx.BaseTransport | None = None,
        events: EventDispatcher | None = None,
        *,
        runtime: OwnedPaymentRuntime | None = None,
    ) -> None:
        self._owns_runtime = runtime is None
        if runtime is not None:
            if methods is not None or events is not None:
                raise ValueError("Pass either methods/events or runtime, not both")
            if not isinstance(runtime, OwnedPaymentRuntime):
                raise TypeError("SyncPaymentTransport requires OwnedPaymentRuntime")
            self._runtime = runtime
        else:
            if methods is None:
                raise ValueError("Pass methods or runtime")
            self._runtime = OwnedPaymentRuntime(methods, events=events)
        self._inner = inner or httpx.HTTPTransport()
        self._events = self._runtime.events

    def _fail(
        self,
        payment: _HttpPayment,
        error: Exception,
        *,
        continuation: bool = False,
        **details: Any,
    ) -> None:
        emit = self._runtime._emit_event_sync if continuation else self._runtime.emit_event_sync
        emit(PAYMENT_FAILED, payment.failed(error, **details))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Send a request and retry one payable 402 response."""
        if request.headers.get("content-type", "").lower().startswith("multipart/form-data"):
            request.read()
        response = self._inner.handle_request(request)
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
                challenge, method = _match_http_challenge(self._runtime, challenges)
            except BaseException:
                _close_response(response)
                raise
        if challenge is None or method is None:
            if parse_error is not None or challenges:
                try:
                    self._runtime.emit_event_sync(
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
                    _close_response(response)
                    raise
            return response

        payment = _HttpPayment(challenges, challenge, method, request, response)
        if _challenge_is_expired(challenge):
            logger.warning("Challenge expired at %s, not paying", challenge.expires)
            try:
                self._fail(payment, ValueError(f"Challenge expired at {challenge.expires}"))
            except BaseException:
                _close_response(response)
                raise
            return response

        try:
            request.read()
        except httpx.StreamConsumed as cause:
            error = PaymentError(
                "Streaming request bodies cannot be replayed after a payment challenge. "
                "Use a buffered body for paid requests."
            )
            try:
                self._fail(payment, error)
            finally:
                _close_response(response)
            raise error from cause
        except BaseException:
            _close_response(response)
            raise

        try:
            response.read()
            response.close()
        except BaseException:
            _close_response(response)
            raise

        with self._runtime._paid_operation():
            try:
                attempt = self._runtime._begin_http_payment(challenge, request)
            except PaymentOutcomeUnknownError as error:
                self._fail(payment, error, continuation=True)
                raise

            try:
                credential = self._runtime._create_credential_sync(
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
                    self._fail(payment, error, continuation=True)
                raise

            try:
                attempt.mark_sent(retry_request)
                payment_response = self._inner.handle_request(retry_request)
            except BaseException as cause:
                if not attempt.sent:
                    attempt.discard()
                    if isinstance(cause, Exception):
                        self._fail(payment, cause, continuation=True)
                    raise
                outcome = attempt.unknown(cause)
                if not isinstance(cause, Exception):
                    raise
                error = payment.unknown(outcome.cause)
                self._fail(payment, error, continuation=True)
                raise error from cause

            try:
                if error := _settle_http_payment(attempt, payment, payment_response):
                    self._fail(
                        payment,
                        error,
                        continuation=True,
                        response=payment_response,
                    )
                    if payment_response.status_code == 402:
                        raise error from error.cause

                _response_request(payment_response, retry_request)
                _propagate_response_cookies(response, payment_response)
                if payment_response.is_success:
                    self._runtime._emit_event_sync(
                        PAYMENT_RESPONSE,
                        payment.event_payload(payment_response),
                    )
                return payment_response
            except BaseException as error:
                if attempt.sent and not attempt.completed and attempt.unknown_outcome is None:
                    attempt.unknown(error)
                _close_response(payment_response)
                raise

    def close(self) -> None:
        """Close the inner transport and an implicitly created runtime."""
        try:
            self._inner.close()
        finally:
            if self._owns_runtime:
                self._runtime.close()
