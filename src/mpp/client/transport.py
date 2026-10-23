"""Payment-aware HTTP transport and client.

Implements automatic 402 Payment Required handling by:
1. Sending the initial request
2. If 402, parsing the WWW-Authenticate challenge
3. Finding a matching method to create credentials
4. Retrying with the credential header selected by the challenge
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import TYPE_CHECKING, Any

import httpx

from mpp import AUTHORIZATION_HEADER, PAYMENT_AUTHORIZATION_HEADER, Challenge, Credential
from mpp._defaults import DEFAULT_PAID_RETRY_TIMEOUT
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
    from collections.abc import Mapping, Sequence


_DEFAULT_MAX_PAYMENT_RETRIES = 3
_ORIGINAL_ORIGIN_EXTENSION = "mpp.original_origin"
_PAYMENT_ATTEMPTED_EXTENSION = "mpp.payment_attempted"
_CREDENTIAL_HEADERS = (AUTHORIZATION_HEADER, PAYMENT_AUTHORIZATION_HEADER)
_MAX_BUFFERED_ERROR_BODY = 64 * 1024
_ERROR_BODY_TIMEOUT = 2.0
_BODY_TRUNCATED_EXTENSION = "mpp.body_truncated"


class _PaidRetryTimeoutUnset:
    def __repr__(self) -> str:
        return f"<inherited, read >= {DEFAULT_PAID_RETRY_TIMEOUT:g}s>"


_PAID_RETRY_TIMEOUT_UNSET: Any = _PaidRetryTimeoutUnset()


def _paid_retry_extensions(
    extensions: dict[str, Any], paid_retry_timeout: float | None
) -> dict[str, Any]:
    """Return request extensions for a paid retry.

    An explicit ``paid_retry_timeout`` replaces the request's timeout and
    ``None`` keeps it. When unset, the inherited read timeout is raised to at
    least ``DEFAULT_PAID_RETRY_TIMEOUT``, since the read is where the server's
    confirmation wait shows up; connect, write and pool timeouts are kept.
    """
    timeout = extensions.get("timeout")
    if paid_retry_timeout is _PAID_RETRY_TIMEOUT_UNSET:
        if not isinstance(timeout, dict) or timeout.get("read") is None:
            return extensions
        read = max(timeout["read"], DEFAULT_PAID_RETRY_TIMEOUT)
        return {**extensions, "timeout": {**timeout, "read": read}}
    if paid_retry_timeout is None:
        return extensions
    return {**extensions, "timeout": httpx.Timeout(paid_retry_timeout).as_dict()}


def _set_payment_credential(headers: httpx.Headers, header: str, value: str) -> None:
    """Attach a Payment credential, preserving ordinary Authorization values."""
    for stale in _CREDENTIAL_HEADERS:
        existing = headers.get(stale)
        if (
            existing is not None
            and stale.lower() == AUTHORIZATION_HEADER.lower()
            and not existing.startswith("Payment ")
        ):
            continue
        if existing is not None:
            del headers[stale]
    headers[header] = value


def _origin(url: httpx.URL) -> tuple[str, str, int | None]:
    port = url.port if url.port is not None else {"http": 80, "https": 443}.get(url.scheme)
    return (url.scheme, url.raw_host.decode("ascii"), port)


def _is_zero_tempo_charge(challenge: Challenge) -> bool:
    if challenge.method != "tempo" or challenge.intent != "charge":
        return False
    try:
        return int(challenge.request["amount"]) == 0
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _payment_origins(
    origins: Sequence[str] | None,
    *,
    parameter: str = "allowed_origins",
) -> frozenset[tuple[str, str, int | None]] | None:
    if origins is None:
        return None
    result = set()
    for value in origins:
        url = httpx.URL(value)
        if (
            url.scheme not in {"http", "https"}
            or not url.host
            or url.userinfo
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
        ):
            raise ValueError(
                f"{parameter} entries must be HTTP(S) origins without credentials or paths"
            )
        result.add(_origin(url))
    return frozenset(result)


def _accept_payment(methods: Sequence[Method]) -> str:
    capabilities = (
        f"{method.name}/{intent}"
        for method in methods
        for intent in getattr(method, "intents", ("charge",))
    )
    return ", ".join(dict.fromkeys(capabilities))


async def _buffer_error_body(response: httpx.Response) -> None:
    """Buffer a paid-retry error body within a size and time bound, then release it.

    The body is diagnostic only. One larger than 64 KiB, or still arriving after
    2 seconds, is cut to what arrived (or dropped if compressed, since a partial
    encoding cannot be decoded reliably) and flagged with
    ``response.extensions["mpp.body_truncated"] = True``.
    """
    stream = response.stream
    if not isinstance(stream, httpx.AsyncByteStream):
        return
    body = bytearray()
    truncated = True
    try:
        async with asyncio.timeout(_ERROR_BODY_TIMEOUT):
            async for chunk in stream:
                body += chunk
                if len(body) > _MAX_BUFFERED_ERROR_BODY:
                    break
            else:
                truncated = False
    except TimeoutError:
        pass
    finally:
        with suppress(Exception):
            await stream.aclose()
    if truncated:
        if response.headers.pop("content-encoding", "identity").lower() != "identity":
            body.clear()
        response.headers.pop("content-length", None)
        response.extensions = {**response.extensions, _BODY_TRUNCATED_EXTENSION: True}
    response.stream = httpx.ByteStream(bytes(body[:_MAX_BUFFERED_ERROR_BODY]))


def _transaction_hash(method: Method, credential: Credential) -> str | None:
    """Return the credential's on-chain hash if the method can derive it."""
    try:
        derive = getattr(method, "transaction_hash", None)
        return None if derive is None else derive(credential)
    except Exception:
        # Reconciliation metadata must never mask the payment outcome itself.
        return None


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

    The paid retry may legitimately wait up to the server's confirmation
    window (30s by default in pympp and mppx) while the payment settles. By
    default it inherits the request's timeout with the read timeout raised to
    at least 35s; an explicit ``paid_retry_timeout`` should be at least as long
    as the server's window. Every other request uses the client's timeout.

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
        allowed_origins: Sequence[str] | None = None,
        trusted_tempo_realms: Mapping[str, str] | None = None,
        max_payment_retries: int = _DEFAULT_MAX_PAYMENT_RETRIES,
        paid_retry_timeout: float | None = _PAID_RETRY_TIMEOUT_UNSET,
    ) -> None:
        """Initialize the transport.

        Args:
            allowed_origins: Exact HTTP(S) origins authorized for automatic payments.
                Includes scheme and port. An empty sequence denies all payments;
                ``None`` preserves unrestricted origin selection. Configure method
                amount and recipient limits separately. Challenge realms are not
                authenticated origins and are not compared with this allowlist.
            trusted_tempo_realms: Explicit origin-to-realm pins for zero-amount
                Tempo charges when a server uses a realm other than its hostname.
            paid_retry_timeout: Timeout in seconds for the paid retry request,
                used exactly when set. ``None`` inherits the request's timeout
                unchanged. When unset, the inherited read timeout is raised to
                at least 35s (``DEFAULT_PAID_RETRY_TIMEOUT``).
        """
        if (methods is None) == (runtime is None):
            raise TypeError("Provide exactly one of methods or runtime")
        if runtime is not None and events is not None:
            raise TypeError("events belongs to the provided runtime")
        self._runtime = (
            runtime if runtime is not None else PaymentRuntime(methods or (), events=events)
        )
        self._allowed_origins = _payment_origins(allowed_origins)
        self._trusted_tempo_realms: dict[tuple[str, str, int | None], str] = {}
        for origin, realm in (trusted_tempo_realms or {}).items():
            _payment_origins([origin], parameter="trusted_tempo_realms")
            self._trusted_tempo_realms[_origin(httpx.URL(origin))] = realm
        self._inner = inner or httpx.AsyncHTTPTransport()
        self._events = self._runtime.events
        self._max_payment_retries = max_payment_retries
        self._paid_retry_timeout = paid_retry_timeout

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
        current_origin = _origin(request.url)
        original_origin = request.extensions.setdefault(_ORIGINAL_ORIGIN_EXTENSION, current_origin)
        supplied_payment = any(
            request.headers.get(header, "").lower().startswith("payment ")
            for header in _CREDENTIAL_HEADERS
        )
        if supplied_payment:
            if current_origin != original_origin:
                raise PaymentError("Refusing to send payment credential across redirect")
            request.extensions[_PAYMENT_ATTEMPTED_EXTENSION] = True
        if supplied_payment or request.extensions.get(_PAYMENT_ATTEMPTED_EXTENSION):
            return await self._inner.handle_async_request(request)

        accept_payment = _accept_payment(self._runtime.methods)
        if accept_payment and "accept-payment" not in request.headers:
            request.headers["Accept-Payment"] = accept_payment

        replayable = not (
            isinstance(request.stream, httpx.AsyncByteStream)
            and not isinstance(request.stream, httpx.SyncByteStream)
        )
        if replayable:
            await request.aread()

        response = await self._inner.handle_async_request(request)

        try:
            for _ in range(self._max_payment_retries):
                if response.status_code != 402:
                    return response

                if original_origin != current_origin:
                    error = PaymentError("Refusing to send payment credential across redirect")
                    await self._events.emit(
                        PAYMENT_FAILED,
                        _client_payment_failed_payload(
                            challenge=None,
                            challenges=[],
                            credential=None,
                            error=error,
                            method=None,
                            request=request,
                            response=response,
                        ),
                    )
                    raise error

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
                        # preserving the 402 response for the caller.
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

                if (
                    self._allowed_origins is not None
                    and current_origin not in self._allowed_origins
                ):
                    error = PaymentError("Payment origin is not allowed")
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
                    raise error

                # A zero-value Tempo transaction still signs the challenge realm
                # into its memo. Do not let a different host obtain a transaction
                # that it can relay to the server named by that realm.
                remaining = challenges
                while (
                    _is_zero_tempo_charge(challenge)
                    and challenge.realm.lower() != request.url.host.lower()
                    and challenge.realm.lower() != request.url.raw_host.decode("ascii").lower()
                    and challenge.realm != self._trusted_tempo_realms.get(current_origin)
                ):
                    error = PaymentError(
                        f"Zero-amount Tempo realm {challenge.realm!r} differs from "
                        f"request host {request.url.host!r}; configure trusted_tempo_realms "
                        "for a known server origin"
                    )
                    remaining = [offer for offer in remaining if offer is not challenge]
                    try:
                        challenge, matched_method = self._runtime.match_challenge(remaining)
                    except ValueError:
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
                        raise error from None

                if not replayable:
                    raise PaymentError(
                        "Streaming request bodies cannot be replayed after a payment challenge. "
                        "Use a buffered body for paid requests."
                    )

                # Release the pool connection before callbacks can make auxiliary requests.
                with suppress(Exception):
                    await response.aclose()

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
                        if response.is_stream_consumed:
                            return response
                        # The matched challenge body was discarded before credential work.
                        # Return a readable empty response rather than a closed network stream.
                        headers = httpx.Headers(response.headers)
                        headers.pop("content-length", None)
                        headers.pop("content-encoding", None)
                        return httpx.Response(
                            response.status_code,
                            headers=headers,
                            content=b"",
                            extensions=response.extensions,
                        )
                    raise

                headers = httpx.Headers(request.headers)
                _set_payment_credential(headers, challenge.credential_header, auth_header)
                retry_request = httpx.Request(
                    method=request.method,
                    url=request.url,
                    headers=headers,
                    content=request.content,
                    extensions=_paid_retry_extensions(request.extensions, self._paid_retry_timeout),
                )

                # HTTPX redirects from the original request, not the inner retry.
                request.extensions[_PAYMENT_ATTEMPTED_EXTENSION] = True
                retry_request.extensions[_PAYMENT_ATTEMPTED_EXTENSION] = True
                try:
                    payment_response = await self._inner.handle_async_request(retry_request)
                    response = payment_response
                    if payment_response.is_server_error:
                        # Release the connection before failure hooks can make auxiliary
                        # requests; the buffered body stays readable for the caller.
                        await _buffer_error_body(payment_response)
                except (Exception, asyncio.CancelledError) as cause:
                    error = PaymentOutcomeUnknownError(
                        challenge,
                        cause,
                        credential=credential,
                        request=request,
                        transaction_hash=_transaction_hash(matched_method, credential),
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
                elif payment_response.is_server_error:
                    # The server may have settled before failing. Report the
                    # credential for reconciliation, return the response, and
                    # never retry: a second attempt could pay twice.
                    error = PaymentOutcomeUnknownError(
                        challenge,
                        httpx.HTTPStatusError(
                            f"Paid retry returned HTTP {payment_response.status_code}",
                            request=request,
                            response=payment_response,
                        ),
                        credential=credential,
                        request=request,
                        transaction_hash=_transaction_hash(matched_method, credential),
                    )
                    try:
                        await self._events.emit(
                            PAYMENT_FAILED,
                            _client_payment_failed_payload(
                                challenge=challenge,
                                challenges=challenges,
                                credential=credential,
                                error=error,
                                method=matched_method,
                                request=request,
                                response=payment_response,
                            ),
                        )
                    except asyncio.CancelledError as cancelled:
                        # Like a cancelled paid request, surface the credential.
                        raise error from cancelled

            return response
        except BaseException:
            # No response escapes to the caller on errors, including cancelled observers.
            with suppress(BaseException):
                await response.aclose()
            raise

    async def aclose(self) -> None:
        """Close the inner transport."""
        await self._inner.aclose()


class Client:
    """HTTP client with automatic payment handling.

    The paid retry may wait up to the server's confirmation window, so unless
    ``paid_retry_timeout`` is set its read timeout is at least 35s; see
    ``PaymentTransport``.

    Example:
        async with Client(methods=[tempo(...)]) as client:
            response = await client.get("https://api.example.com/resource")
    """

    def __init__(
        self,
        methods: Sequence[Method] | None = None,
        *,
        runtime: PaymentRuntime | None = None,
        allowed_origins: Sequence[str] | None = None,
        trusted_tempo_realms: Mapping[str, str] | None = None,
        max_payment_retries: int = _DEFAULT_MAX_PAYMENT_RETRIES,
        paid_retry_timeout: float | None = _PAID_RETRY_TIMEOUT_UNSET,
    ) -> None:
        self._transport = PaymentTransport(
            methods,
            runtime=runtime,
            allowed_origins=allowed_origins,
            trusted_tempo_realms=trusted_tempo_realms,
            max_payment_retries=max_payment_retries,
            paid_retry_timeout=paid_retry_timeout,
        )
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
    paid_retry_timeout: float | None = _PAID_RETRY_TIMEOUT_UNSET,
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
    async with Client(methods, paid_retry_timeout=paid_retry_timeout) as client:
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
