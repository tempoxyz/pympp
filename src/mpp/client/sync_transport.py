"""Synchronous payment-aware httpx transport."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from mpp.errors import PaymentError, PaymentOutcomeUnknownError
from mpp.events import PAYMENT_FAILED, PAYMENT_RESPONSE, EventDispatcher
from mpp.runtime import Method, PaymentRuntime, _challenge_is_expired

from .transport import (
    _apply_response_cookies,
    _bind_response_request,
    _challenged_request,
    _client_payment_failed_payload,
    _copy_request,
    _EventHandlers,
    _match_http_challenge,
    _OutcomeStream,
    _payment_challenges,
    _propagate_response_cookies,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


def _close_response(response: httpx.Response) -> None:
    try:
        response.close()
    except BaseException:
        pass


class _SyncOutcomeStream(_OutcomeStream, httpx.SyncByteStream):
    def __iter__(self):
        try:
            yield from self._stream
        except BaseException as error:
            self._mark_unknown(error)
            raise
        else:
            self._mark_complete()

    def close(self) -> None:
        try:
            self._stream.close()
        finally:
            self._mark_unknown(RuntimeError("Paid response body was not fully consumed"))


class SyncPaymentTransport(_EventHandlers, httpx.BaseTransport):
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

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Send a request and retry one 402 with a payment credential."""
        with self._runtime._httpx_operation_scope(request):
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

        try:
            challenged_request = _challenged_request(response, request)
            if not self._runtime.allows_http_payment(challenged_request.url):
                return response

            challenges, parse_error = _payment_challenges(response)
            if challenges:
                self._runtime.start()

            challenge, method = _match_http_challenge(self._runtime, challenges)

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

            response.read()
        except BaseException:
            _close_response(response)
            raise

        try:
            attempt = self._runtime._begin_http_payment(challenge, challenged_request)
        except PaymentOutcomeUnknownError as error:
            self._runtime.emit_event_sync(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=error.credential,
                    error=error,
                    method=method,
                    request=challenged_request,
                    response=response,
                ),
            )
            raise

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
        except BaseException as error:
            self._runtime._discard_http_payment(attempt)
            if not isinstance(error, Exception):
                raise
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
        self._runtime._set_http_payment_credential(attempt, credential)

        try:
            headers = httpx.Headers(challenged_request.headers)
            headers["Authorization"] = auth_header
            retry_request = _copy_request(challenged_request, headers=headers)
            _apply_response_cookies(response, challenged_request, retry_request)

            with self._runtime._paid_operation():
                try:
                    self._runtime._mark_http_payment_sent(attempt, retry_request)
                except PaymentOutcomeUnknownError as error:
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
                try:
                    payment_response = self._inner.handle_request(retry_request)
                except BaseException as cause:
                    self._runtime._mark_http_payment_unknown(attempt, cause)
                    if not isinstance(cause, Exception):
                        raise
                    error = PaymentOutcomeUnknownError(
                        challenge,
                        cause,
                        credential=credential,
                        request=challenged_request,
                    )
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
                    raise error from cause

                _bind_response_request(payment_response, retry_request)
                _propagate_response_cookies(response, payment_response)

                try:
                    if payment_response.status_code == 402:
                        cause = RuntimeError(
                            "Server returned another payment challenge after receiving a credential"
                        )
                        self._runtime._mark_http_payment_unknown(attempt, cause)
                        error = PaymentOutcomeUnknownError(
                            challenge,
                            cause,
                            credential=credential,
                            request=challenged_request,
                        )
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
                        raise error from cause

                    if payment_response.status_code >= 400:
                        cause = RuntimeError(
                            f"Credentialed request returned HTTP {payment_response.status_code}"
                        )
                        self._runtime._mark_http_payment_unknown(attempt, cause)
                        self._runtime.emit_event_sync(
                            PAYMENT_FAILED,
                            _client_payment_failed_payload(
                                challenge=challenge,
                                challenges=challenges,
                                credential=credential,
                                error=PaymentOutcomeUnknownError(
                                    challenge,
                                    cause,
                                    credential=credential,
                                    request=challenged_request,
                                ),
                                method=method,
                                request=challenged_request,
                                response=payment_response,
                            ),
                        )
                    elif payment_response.is_stream_consumed:
                        self._runtime._mark_http_response_body_complete(attempt)
                    else:
                        payment_response.stream = _SyncOutcomeStream(
                            payment_response.stream,
                            self._runtime,
                            attempt,
                        )

                    if payment_response.is_success:
                        self._runtime.emit_event_sync(
                            PAYMENT_RESPONSE,
                            {
                                "challenge": challenge,
                                "challenges": challenges,
                                "credential": credential,
                                "method": method,
                                "request": challenged_request,
                                "response": payment_response,
                                "protocol": "http",
                            },
                        )
                except BaseException:
                    _close_response(payment_response)
                    raise
                return payment_response
        except BaseException:
            if not attempt.sent:
                self._runtime._discard_http_payment(attempt)
            raise

    def close(self) -> None:
        """Close the inner transport and any runtime created by this transport."""
        try:
            self._inner.close()
        finally:
            if self._owns_runtime:
                self._runtime.close()
