"""Private HTTP payment primitives shared by HTTPX transports."""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from http.cookies import CookieError, SimpleCookie
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from mpp import Challenge, Credential
from mpp._parsing import ParseError
from mpp.errors import PaymentOutcomeUnknownError
from mpp.events import ClientPaymentFailedPayload

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mpp.runtime import Method, OwnedPaymentRuntime, PaymentRuntime

_COOKIE_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")
_PAYMENT_MARKER = "mpp.payment_attempt"
_PAYMENT_SENT = "mpp.payment_sent"
# Unknown outcomes cannot be safely evicted; block payments before retention is unbounded.
_MAX_UNRECONCILED_OUTCOMES = 1024


@dataclass(slots=True)
class _Reconciliation:
    """Shared reset token for markers retained on detached requests."""

    reconciled: bool = False


@dataclass(frozen=True, slots=True)
class _UnknownOutcome:
    """Retained sent payment that must be reconciled before retry."""

    challenge: Challenge
    credential: Credential | None
    cause: BaseException
    request: httpx.Request
    reconciliation: _Reconciliation


@dataclass(eq=False, slots=True)
class _HttpPaymentAttempt:
    ledger: _HttpPaymentLedger
    keys: tuple[str, str]
    challenge: Challenge
    request: httpx.Request
    credential: Credential | None = None
    retry_request: httpx.Request | None = None
    sent: bool = False
    completed: bool = False
    unknown_outcome: _UnknownOutcome | None = None

    def mark_sent(self, request: httpx.Request) -> None:
        self.ledger.mark_sent(self, request)

    def unknown(self, cause: BaseException) -> _UnknownOutcome:
        return self.ledger.mark_unknown(self, cause)

    def complete(self) -> None:
        self.ledger.complete(self)

    def discard(self) -> None:
        self.ledger.discard(self)


class _HttpPaymentLedger:
    """Fail closed around concurrent or uncertain HTTP payment attempts."""

    def __init__(self) -> None:
        self._entries: dict[str, _HttpPaymentAttempt | _UnknownOutcome] = {}
        self._unreconciled_count = 0
        self._circuit: _UnknownOutcome | None = None
        self._reconciliation = _Reconciliation()
        self._lock = threading.RLock()

    def begin(self, challenge: Challenge, request: httpx.Request) -> _HttpPaymentAttempt:
        with self._lock:
            return self._begin(challenge, request)

    def _begin(self, challenge: Challenge, request: httpx.Request) -> _HttpPaymentAttempt:
        marker = request.extensions.get(_PAYMENT_MARKER)
        if isinstance(marker, _HttpPaymentAttempt):
            raise _outcome_error(marker)
        if isinstance(marker, _UnknownOutcome):
            if not marker.reconciliation.reconciled:
                raise _outcome_error(marker)
            request.extensions.pop(_PAYMENT_MARKER)
        if self._circuit is not None:
            raise _outcome_error(self._circuit)

        challenge_key, operation_key, idempotent = _attempt_keys(challenge, request)
        existing = self._entries.get(challenge_key)
        operation = self._entries.get(operation_key)
        if existing is None and (idempotent or isinstance(operation, _UnknownOutcome)):
            existing = operation
        if existing is not None:
            raise _outcome_error(existing)

        attempt = _HttpPaymentAttempt(
            self,
            (challenge_key, operation_key),
            challenge,
            request,
        )
        self._entries[challenge_key] = attempt
        if idempotent:
            self._entries[operation_key] = attempt
        return attempt

    def mark_sent(self, attempt: _HttpPaymentAttempt, request: httpx.Request) -> None:
        with self._lock:
            self._mark_sent(attempt, request)

    def _mark_sent(self, attempt: _HttpPaymentAttempt, request: httpx.Request) -> None:
        if self._circuit is not None:
            self.discard(attempt)
            raise _outcome_error(self._circuit)
        if isinstance(operation := self._entries.get(attempt.keys[1]), _UnknownOutcome):
            self.discard(attempt)
            raise _outcome_error(operation)
        attempt.sent = True
        attempt.retry_request = request
        for current in (attempt.request, request):
            current.extensions[_PAYMENT_MARKER] = attempt
            current.extensions[_PAYMENT_SENT] = id(current)

    def mark_unknown(
        self,
        attempt: _HttpPaymentAttempt,
        cause: BaseException,
    ) -> _UnknownOutcome:
        with self._lock:
            return self._mark_unknown(attempt, cause)

    def _mark_unknown(
        self,
        attempt: _HttpPaymentAttempt,
        cause: BaseException,
    ) -> _UnknownOutcome:
        if attempt.unknown_outcome is not None:
            return attempt.unknown_outcome

        outcome = _UnknownOutcome(
            challenge=attempt.challenge,
            credential=attempt.credential,
            cause=_compact_cause(cause),
            request=httpx.Request(attempt.request.method, attempt.request.url),
            reconciliation=self._reconciliation,
        )
        attempt.unknown_outcome = outcome
        self._remove(attempt)
        for request in (attempt.request, attempt.retry_request):
            if request is not None:
                request.extensions[_PAYMENT_MARKER] = outcome

        if self._circuit is not None:
            return outcome
        for key in attempt.keys:
            self._entries[key] = outcome
        self._unreconciled_count += 1
        if self._unreconciled_count >= _MAX_UNRECONCILED_OUTCOMES:
            self._circuit = outcome
        return outcome

    def complete(self, attempt: _HttpPaymentAttempt) -> None:
        with self._lock:
            self._complete(attempt)

    def _complete(self, attempt: _HttpPaymentAttempt) -> None:
        if attempt.completed or attempt.unknown_outcome is not None:
            return
        attempt.completed = True
        self._remove(attempt)
        for request in (attempt.request, attempt.retry_request):
            if request is not None and request.extensions.get(_PAYMENT_MARKER) is attempt:
                request.extensions.pop(_PAYMENT_MARKER, None)

    def discard(self, attempt: _HttpPaymentAttempt) -> None:
        with self._lock:
            if not attempt.sent:
                self._complete(attempt)

    def reset(self, *, reconciled: bool) -> None:
        with self._lock:
            if not reconciled:
                raise ValueError(
                    "Unknown payment outcomes must be externally reconciled before reset"
                )
            self._reconciliation.reconciled = True
            self._reconciliation = _Reconciliation()
            self._entries = {
                key: entry
                for key, entry in self._entries.items()
                if isinstance(entry, _HttpPaymentAttempt)
            }
            self._unreconciled_count = 0
            self._circuit = None

    def _remove(self, attempt: _HttpPaymentAttempt) -> None:
        for key in attempt.keys:
            if self._entries.get(key) is attempt:
                self._entries.pop(key)


@dataclass(slots=True)
class _HttpPayment:
    challenges: list[Challenge]
    challenge: Challenge
    method: Method
    request: httpx.Request
    response: httpx.Response
    credential: Credential | None = None

    def event_payload(self, response: httpx.Response | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "challenge": self.challenge,
            "challenges": self.challenges,
            "method": self.method,
            "request": self.request,
            "response": response if response is not None else self.response,
        }
        if self.credential is not None:
            payload["credential"] = self.credential
        return payload

    def failed(
        self,
        error: Exception,
        *,
        response: httpx.Response | None = None,
    ) -> ClientPaymentFailedPayload:
        credential = self.credential
        if isinstance(error, PaymentOutcomeUnknownError):
            credential = error.credential
        return _failed_payload(
            challenge=self.challenge,
            challenges=self.challenges,
            credential=credential,
            error=error,
            method=self.method,
            request=self.request,
            response=response if response is not None else self.response,
        )

    def unknown(self, cause: BaseException) -> PaymentOutcomeUnknownError:
        return PaymentOutcomeUnknownError(
            self.challenge,
            cause,
            credential=self.credential,
            request=self.request,
        )

    def retry_request(self, authorization: str) -> httpx.Request:
        headers = httpx.Headers(self.request.headers)
        headers["authorization"] = authorization
        retry = _copy_request(self.request, headers=headers)
        _apply_response_cookies(self.response, self.request, retry)
        return retry


def _settle_http_payment(
    attempt: _HttpPaymentAttempt,
    payment: _HttpPayment,
    response: httpx.Response,
) -> PaymentOutcomeUnknownError | None:
    if response.status_code < 400:
        attempt.complete()
        return None
    detail = (
        "Server returned another payment challenge after receiving a credential"
        if response.status_code == 402
        else f"Credentialed request returned HTTP {response.status_code}"
    )
    cause = RuntimeError(detail)
    attempt.unknown(cause)
    return payment.unknown(cause)


class _AllowedOrigins:
    def __init__(self, allowed: Sequence[str] | None) -> None:
        self._allow_all = allowed is None
        values = (allowed,) if isinstance(allowed, str) else allowed or ()
        self._origins = {origin for value in values if (origin := _origin(value)) is not None}

    def allows(self, url: httpx.URL) -> bool:
        return self._allow_all or _httpx_origin(url) in self._origins


def _payment_challenges(response: httpx.Response) -> tuple[list[Challenge], ParseError | None]:
    challenges: list[Challenge] = []
    parse_error: ParseError | None = None
    for header in response.headers.get_list("www-authenticate"):
        for value in _authentication_challenges(header):
            if not value.lower().startswith("payment "):
                continue
            try:
                challenges.append(Challenge.from_www_authenticate(value))
            except ParseError as error:
                parse_error = error
    return challenges, parse_error


def _authentication_challenges(header: str) -> list[str]:
    """Split a WWW-Authenticate field without splitting auth-param lists."""
    challenges: list[str] = []
    start = 0
    quoted = escaped = False
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
        after_token = token_end
        while after_token < len(header) and header[after_token] in " \t":
            after_token += 1
        if (
            token_end == next_index
            or (after_token < len(header) and header[after_token] == "=")
            or (token_end < len(header) and header[token_end] not in " \t")
        ):
            continue

        if challenge := header[start:index].strip():
            challenges.append(challenge)
        start = next_index
    if challenge := header[start:].strip():
        challenges.append(challenge)
    return challenges


def _challenge_is_expired(challenge: Challenge) -> bool:
    if challenge.expires is None:
        return False
    if not challenge.expires:
        return True
    try:
        expires = datetime.fromisoformat(challenge.expires.replace("Z", "+00:00"))
        return expires.tzinfo is None or expires.utcoffset() is None or expires < datetime.now(UTC)
    except (OverflowError, TypeError, ValueError):
        return True


def _match_http_challenge(
    runtime: PaymentRuntime | OwnedPaymentRuntime,
    challenges: list[Challenge],
) -> tuple[Challenge | None, Method | None]:
    try:
        return runtime.match_challenge(
            sorted(challenges, key=_challenge_is_expired),
            prefer_method_order=False,
        )
    except ValueError:
        return None, None


def _failed_payload(
    *,
    challenge: Challenge | None,
    challenges: list[Challenge],
    credential: Credential | None | object,
    error: Exception,
    method: Method | None,
    request: httpx.Request,
    response: httpx.Response,
) -> ClientPaymentFailedPayload:
    return {
        "challenge": challenge,
        "challenges": challenges,
        "credential": credential if isinstance(credential, Credential) else None,
        "error": error,
        "method": method,
        "request": request,
        "response": response,
    }


def _copy_request(
    request: httpx.Request,
    *,
    headers: httpx.Headers | None = None,
) -> httpx.Request:
    return httpx.Request(
        request.method,
        request.url,
        headers=request.headers if headers is None else headers,
        content=request.content,
        extensions=dict(request.extensions),
    )


def _response_request(
    response: httpx.Response,
    fallback: httpx.Request,
) -> httpx.Request:
    try:
        return response.request
    except RuntimeError:
        response.request = fallback
        return fallback


def _apply_response_cookies(
    response: httpx.Response,
    source_request: httpx.Request,
    target_request: httpx.Request,
) -> None:
    """Apply hidden 402 cookies before HTTPX's outer client can observe them."""
    headers = response.headers.get_list("set-cookie")
    if not headers:
        return

    _response_request(response, source_request)
    cookies = httpx.Cookies()
    cookies.extract_cookies(response)
    cookie_request = httpx.Request(target_request.method, target_request.url)
    cookies.set_cookie_header(cookie_request)
    replacements = [
        part.strip() for part in cookie_request.headers.get("cookie", "").split(";") if part.strip()
    ]
    names = {part.split("=", 1)[0].strip() for part in replacements}

    for header in headers:
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except CookieError:
            continue
        for name, cookie in parsed.items():
            if (
                name not in names
                and _cookie_applies(cookie, target_request.url)
                and _cookie_replaced(response, name, cookie, target_request.url)
            ):
                names.add(name)

    existing = [
        part.strip() for part in target_request.headers.get("cookie", "").split(";") if part.strip()
    ]
    retained = [part for part in existing if part.split("=", 1)[0].strip() not in names]
    if merged := "; ".join((*replacements, *retained)):
        target_request.headers["cookie"] = merged
    else:
        target_request.headers.pop("cookie", None)


def _propagate_response_cookies(source: httpx.Response, target: httpx.Response) -> None:
    """Expose hidden 402 cookies to the outer HTTPX client's cookie jar."""
    if source is target:
        return
    values = source.headers.get_list("set-cookie")
    if not values:
        return
    target_values = target.headers.get_list("set-cookie")
    target.headers.pop("set-cookie", None)
    target.headers.update([("set-cookie", value) for value in (*values, *target_values)])


def _cookie_applies(cookie: Any, url: httpx.URL) -> bool:
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


def _cookie_replaced(
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
    if (path := cookie["path"]).startswith("/"):
        return path
    request_path = _cookie_request_path(url)
    last_slash = request_path.rfind("/")
    return "/" if last_slash <= 0 else request_path[:last_slash]


def _cookie_request_path(url: httpx.URL) -> str:
    path = url.raw_path.partition(b"?")[0].decode("ascii")
    path = quote(path, safe="%/;:@&=+$,!~*'()")
    return _COOKIE_ESCAPE.sub(lambda match: match[0].upper(), path) or "/"


async def _close_response(response: httpx.Response) -> None:
    try:
        await response.aclose()
    except BaseException:
        pass


def _attempt_keys(challenge: Challenge, request: httpx.Request) -> tuple[str, str, bool]:
    origin = repr(_httpx_origin(request.url))
    challenge_key = _digest("challenge", origin, challenge.id)
    if idempotency_key := request.headers.get("idempotency-key"):
        idempotent = True
        operation_key = _digest(
            "idempotency",
            request.method,
            str(request.url).split("#", 1)[0],
            idempotency_key,
        )
    else:
        idempotent = False
        operation_key = _digest(
            "request",
            request.method,
            str(request.url).split("#", 1)[0],
            hashlib.sha256(request.content).hexdigest(),
        )
    return challenge_key, operation_key, idempotent


def _digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def _outcome_error(entry: _HttpPaymentAttempt | _UnknownOutcome) -> PaymentOutcomeUnknownError:
    cause = (
        entry.cause
        if isinstance(entry, _UnknownOutcome)
        else RuntimeError("A matching payment attempt is already in progress")
    )
    return PaymentOutcomeUnknownError(
        entry.challenge,
        cause,
        credential=entry.credential,
        request=entry.request,
    )


def _compact_cause(cause: BaseException) -> BaseException:
    try:
        compact = type(cause)(str(cause))
    except BaseException:
        compact = RuntimeError(f"{type(cause).__name__}: {cause}")
    compact.__traceback__ = compact.__cause__ = compact.__context__ = None
    return compact


def _origin(value: str) -> tuple[str, str, int | None] | None:
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, TypeError, UnicodeError):
        return None
    return _httpx_origin(url) if url.scheme and url.raw_host else None


def _httpx_origin(url: httpx.URL) -> tuple[str, str, int | None]:
    scheme = url.scheme.casefold()
    port = url.port
    if port == {"http": 80, "https": 443}.get(scheme):
        port = None
    return scheme, url.raw_host.decode("ascii").casefold(), port
