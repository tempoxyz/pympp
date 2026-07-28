"""Payment-aware HTTP transport and client.

Implements automatic 402 Payment Required handling by:
1. Sending the initial request
2. If 402, parsing the WWW-Authenticate challenge
3. Finding a matching method to create credentials
4. Retrying with the Authorization header
"""

from __future__ import annotations

import logging
import re
from http.cookies import CookieError, SimpleCookie
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from mpp import Challenge, Credential
from mpp._parsing import ParseError
from mpp.errors import PaymentError, PaymentOutcomeUnknownError
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
    Method,
    PaymentRuntime,
    _CallerLoopRuntime,
    _challenge_is_expired,
    _HttpPaymentAttempt,
)

logger = logging.getLogger(__name__)
_COOKIE_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")

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
        response.request = fallback
        return fallback


def _copy_request(
    request: httpx.Request,
    *,
    headers: httpx.Headers | None = None,
) -> httpx.Request:
    return httpx.Request(
        method=request.method,
        url=request.url,
        headers=request.headers if headers is None else headers,
        content=request.content,
        extensions=request.extensions,
    )


def _apply_response_cookies(
    response: httpx.Response,
    source_request: httpx.Request,
    target_request: httpx.Request,
) -> None:
    """Apply cookies from an internal 402 response to its immediate retry."""
    set_cookie_headers = response.headers.get_list("set-cookie")
    if not set_cookie_headers:
        return

    _bind_response_request(response, source_request)
    cookies = httpx.Cookies()
    cookies.extract_cookies(response)
    cookie_request = httpx.Request(target_request.method, target_request.url)
    cookies.set_cookie_header(cookie_request)
    replacement_parts = [
        part.strip() for part in cookie_request.headers.get("cookie", "").split(";") if part.strip()
    ]
    replacement_names = {part.split("=", 1)[0].strip() for part in replacement_parts}

    for header in set_cookie_headers:
        replacement = SimpleCookie()
        try:
            replacement.load(header)
        except CookieError:
            continue
        for name, cookie in replacement.items():
            if (
                name not in replacement_names
                and _cookie_applies_to_request(cookie, target_request.url)
                and _cookie_replaced_in_jar(response, name, cookie, target_request.url)
            ):
                replacement_names.add(name)

    existing_parts = [
        part.strip() for part in target_request.headers.get("cookie", "").split(";") if part.strip()
    ]
    retained_parts = [
        part for part in existing_parts if part.split("=", 1)[0].strip() not in replacement_names
    ]
    merged = "; ".join((*replacement_parts, *retained_parts))
    if merged:
        target_request.headers["cookie"] = merged
    else:
        target_request.headers.pop("cookie", None)


def _cookie_applies_to_request(cookie: Any, url: httpx.URL) -> bool:
    host = url.raw_host.decode("ascii").casefold()
    domain = cookie["domain"].lstrip(".").casefold()
    if domain and host != domain and not host.endswith(f".{domain}"):
        return False
    if cookie["secure"] and url.scheme.casefold() != "https":
        return False

    request_path = _cookie_request_path(url)
    cookie_path = _cookie_path(cookie, url)
    return request_path == cookie_path or (
        request_path.startswith(cookie_path)
        and (cookie_path.endswith("/") or request_path[len(cookie_path) :].startswith("/"))
    )


def _cookie_replaced_in_jar(
    response: httpx.Response,
    name: str,
    cookie: Any,
    url: httpx.URL,
) -> bool:
    explicit_domain = cookie["domain"].lstrip(".").casefold()
    domain = explicit_domain or url.raw_host.decode("ascii").casefold()
    path = _cookie_path(cookie, url)
    sentinel = "mpp-existing-cookie"
    probe = httpx.Cookies()
    probe.set(name, sentinel, domain=f".{domain}" if explicit_domain else domain, path=path)
    probe.extract_cookies(response)
    return not any(
        item.name == name
        and item.domain.lstrip(".").casefold() == domain
        and item.path == path
        and item.value == sentinel
        for item in probe.jar
    )


def _cookie_path(cookie: Any, url: httpx.URL) -> str:
    cookie_path = cookie["path"]
    if cookie_path.startswith("/"):
        return cookie_path
    request_path = _cookie_request_path(url)
    last_slash = request_path.rfind("/")
    return "/" if last_slash <= 0 else request_path[:last_slash]


def _cookie_request_path(url: httpx.URL) -> str:
    path = url.raw_path.partition(b"?")[0].decode("ascii")
    path = quote(path, safe="%/;:@&=+$,!~*'()")
    return _COOKIE_ESCAPE.sub(lambda match: match[0].upper(), path) or "/"


def _propagate_response_cookies(
    source: httpx.Response,
    target: httpx.Response,
) -> None:
    """Expose cookies from an internal 402 response on the returned response."""
    if source is target:
        return
    source_values = source.headers.get_list("set-cookie")
    if not source_values:
        return
    target_values = target.headers.get_list("set-cookie")
    target.headers.pop("set-cookie", None)
    target.headers.update([("set-cookie", value) for value in (*source_values, *target_values)])


def _bind_response_request(response: httpx.Response, request: httpx.Request) -> None:
    try:
        _ = response.request
    except RuntimeError:
        response.request = request


async def _aclose_response(response: httpx.Response) -> None:
    try:
        await response.aclose()
    except BaseException:
        pass


def _authentication_challenges(header: str) -> list[str]:
    """Split a WWW-Authenticate field without splitting auth-param lists."""
    challenges: list[str] = []
    start = 0
    quoted = False
    escaped = False
    token_chars = frozenset("!#$%&'*+-.^_`|~")

    for index, character in enumerate(header):
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
            continue
        if character != ",":
            continue

        next_index = index + 1
        while next_index < len(header) and header[next_index] in " \t":
            next_index += 1
        token_end = next_index
        while token_end < len(header) and (
            header[token_end].isalnum() or header[token_end] in token_chars
        ):
            token_end += 1
        if token_end == next_index:
            continue

        after_token = token_end
        while after_token < len(header) and header[after_token] in " \t":
            after_token += 1
        if after_token < len(header) and header[after_token] == "=":
            continue
        if token_end < len(header) and header[token_end] not in " \t":
            continue

        challenge = header[start:index].strip()
        if challenge:
            challenges.append(challenge)
        start = next_index

    challenge = header[start:].strip()
    if challenge:
        challenges.append(challenge)
    return challenges


def _payment_challenges(response: httpx.Response) -> tuple[list[Challenge], ParseError | None]:
    challenges: list[Challenge] = []
    parse_error: ParseError | None = None
    for header in response.headers.get_list("www-authenticate"):
        for authentication_challenge in _authentication_challenges(header):
            if not authentication_challenge.lower().startswith("payment "):
                continue
            try:
                challenges.append(Challenge.from_www_authenticate(authentication_challenge))
            except ParseError as error:
                parse_error = error
    return challenges, parse_error


def _match_http_challenge(
    runtime: PaymentRuntime,
    challenges: list[Challenge],
) -> tuple[Challenge | None, Method | None]:
    current: list[Challenge] = []
    expired: list[Challenge] = []
    for challenge in challenges:
        (expired if _challenge_is_expired(challenge) else current).append(challenge)
    for candidates in (current, expired):
        if not candidates:
            continue
        try:
            return runtime.match_challenge(
                candidates,
                prefer_method_order=False,
                allow_name_only=True,
            )
        except ValueError:
            pass
    return None, None


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


class _OutcomeStream:
    def __init__(
        self,
        stream: Any,
        runtime: PaymentRuntime,
        attempt: _HttpPaymentAttempt,
    ) -> None:
        self._stream = stream
        self._runtime: PaymentRuntime | None = runtime
        self._attempt: _HttpPaymentAttempt | None = attempt

    def _take_attempt(self) -> tuple[PaymentRuntime, _HttpPaymentAttempt] | None:
        runtime, attempt = self._runtime, self._attempt
        self._runtime = None
        self._attempt = None
        if runtime is None or attempt is None:
            return None
        return runtime, attempt

    def _mark_complete(self) -> None:
        if state := self._take_attempt():
            state[0]._mark_http_response_body_complete(state[1])

    def _mark_unknown(self, error: BaseException) -> None:
        if state := self._take_attempt():
            state[0]._mark_http_payment_unknown(state[1], error)


class _AsyncOutcomeStream(_OutcomeStream, httpx.AsyncByteStream):
    async def __aiter__(self):
        try:
            async for chunk in self._stream:
                yield chunk
        except BaseException as error:
            self._mark_unknown(error)
            raise
        else:
            self._mark_complete()

    async def aclose(self) -> None:
        try:
            await self._stream.aclose()
        finally:
            self._mark_unknown(RuntimeError("Paid response body was not fully consumed"))


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
            self._runtime = _CallerLoopRuntime(methods or [], events=events)
        self._inner = inner or httpx.AsyncHTTPTransport()
        self._events = self._runtime.events

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Handle request, automatically retrying on 402 with credentials."""
        with self._runtime._httpx_operation_scope(request):
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

        try:
            # A high-level send may have followed redirects before returning the
            # 402. Apply policy and retry against the request that was challenged.
            challenged_request = _challenged_request(response, request)
            if not self._runtime.allows_http_payment(challenged_request.url):
                return response

            challenges, parse_error = _payment_challenges(response)
            if challenges:
                await self._runtime.astart()

            challenge, matched_method = _match_http_challenge(self._runtime, challenges)

            if challenge is None or matched_method is None:
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

            expired = _challenge_is_expired(challenge)
            if expired:
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

            await response.aread()
        except BaseException:
            await _aclose_response(response)
            raise

        try:
            attempt = self._runtime._begin_http_payment(challenge, challenged_request)
        except PaymentOutcomeUnknownError as error:
            await self._runtime.emit_event(
                PAYMENT_FAILED,
                _client_payment_failed_payload(
                    challenge=challenge,
                    challenges=challenges,
                    credential=error.credential,
                    error=error,
                    method=matched_method,
                    request=challenged_request,
                    response=response,
                ),
            )
            raise

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
        except BaseException as error:
            self._runtime._discard_http_payment(attempt)
            if not isinstance(error, Exception):
                raise
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
                try:
                    payment_response = await self._inner.handle_async_request(retry_request)
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
                        raise error from cause

                    if payment_response.status_code >= 400:
                        cause = RuntimeError(
                            f"Credentialed request returned HTTP {payment_response.status_code}"
                        )
                        self._runtime._mark_http_payment_unknown(attempt, cause)
                        await self._runtime.emit_event(
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
                                method=matched_method,
                                request=challenged_request,
                                response=payment_response,
                            ),
                        )
                    elif payment_response.is_stream_consumed:
                        self._runtime._mark_http_response_body_complete(attempt)
                    else:
                        payment_response.stream = _AsyncOutcomeStream(
                            payment_response.stream,
                            self._runtime,
                            attempt,
                        )

                    if payment_response.is_success:
                        await self._runtime.emit_event(
                            PAYMENT_RESPONSE,
                            {
                                "challenge": challenge,
                                "challenges": challenges,
                                "credential": credential,
                                "method": matched_method,
                                "request": challenged_request,
                                "response": payment_response,
                                "protocol": "http",
                            },
                        )
                except BaseException:
                    await _aclose_response(payment_response)
                    raise
                return payment_response
        except BaseException:
            if not attempt.sent:
                self._runtime._discard_http_payment(attempt)
            raise

    async def aclose(self) -> None:
        """Close the inner transport."""
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
