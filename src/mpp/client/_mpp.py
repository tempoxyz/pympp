"""The client payment engine: automatic 402 handling over ``httpx``."""

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Self

import httpx

from mpp import _accept_payment
from mpp import expires as _expires
from mpp.challenge import Challenge
from mpp.client._events import (
    ChallengeReceived,
    ClientEventDispatcher,
    ClientPaymentFailed,
    CredentialCreated,
    PaymentResponse,
    Unsubscribe,
)
from mpp.client._protocols import rebuild_request
from mpp.client._transport import ClientTransport, HttpTransport
from mpp.constants import Header
from mpp.errors import PaymentOutcomeUnknownError
from mpp.method import (
    Attempt,
    AttemptOutcome,
    ClientMethod,
    CredentialParams,
    PrepareParams,
    ResponseParams,
    resolve,
)

DEFAULT_MAX_PAYMENT_RETRIES = 3
MAX_ERROR_BODY_BYTES = 64 * 1024
ERROR_BODY_TIMEOUT_SECONDS = 2.0
BODY_TRUNCATED_HEADER = "Mppx-Body-Truncated"
"""Set on a paid-retry error response whose body was cut off while buffering."""

CONTEXT_EXTENSION = "mpp.context"
"""``httpx`` request extension carrying the per-request credential context."""
ORDER_CHALLENGES_EXTENSION = "mpp.order_challenges"
"""``httpx`` request extension carrying a per-request ``order_challenges`` hook."""
_ORIGIN_EXTENSION = "mpp.origin"
_PAID_EXTENSION = "mpp.paid"

type AcceptPaymentPolicy = Literal["always", "same-origin", "never"] | Sequence[str]
"""When to inject ``Accept-Payment``: always, never, same origin (always outside browsers) or
for a list of origins (``"*.example.com"`` matches subdomains)."""

type ChallengeCandidate = _accept_payment.ChallengeCandidate[ClientMethod]
type OrderChallenges = Callable[
    [Sequence[ChallengeCandidate]],
    Sequence[ChallengeCandidate] | Awaitable[Sequence[ChallengeCandidate]],
]
"""Filters/sorts supported challenge candidates; the first returned candidate is paid."""

type OnChallenge = Callable[[Challenge, Callable[..., Awaitable[str]]], Awaitable[str | None]]
"""Called when no event handler supplied a credential: ``(challenge, create_credential)``."""

type Methods = Sequence[ClientMethod | Sequence[ClientMethod]]


def _flatten(methods: Methods) -> tuple[ClientMethod, ...]:
    flat: list[ClientMethod] = []
    for entry in methods:
        if isinstance(entry, ClientMethod):
            flat.append(entry)
        else:
            flat.extend(entry)
    return tuple(flat)


def validate_credential_header_value(credential: str) -> None:
    """Rejects empty credentials and header injection."""
    if not credential.strip():
        raise ValueError("Credential header value must be non-empty")
    if "\r" in credential or "\n" in credential:
        raise ValueError("Credential header value contains illegal newline characters")


def _origin(url: httpx.URL) -> str:
    port = f":{url.port}" if url.port is not None else ""
    return f"{url.scheme}://{url.host}{port}"


type _Origin = tuple[str, str, int | None]


def _payment_origin(url: httpx.URL) -> _Origin:
    """Scheme, host and port with the scheme's default port filled in."""
    port = url.port if url.port is not None else {"http": 80, "https": 443}.get(url.scheme)
    return (url.scheme, url.raw_host.decode("ascii").lower(), port)


def _allowed_origins(origins: Sequence[str] | None) -> frozenset[_Origin] | None:
    if origins is None:
        return None
    if isinstance(origins, str):
        raise TypeError("allowed_origins must be a sequence of origins, not a string")
    result: set[_Origin] = set()
    for value in origins:
        url = httpx.URL(value)
        if (
            url.scheme not in ("http", "https")
            or not url.host
            or url.userinfo
            or url.path not in ("", "/")
            or url.query
            or url.fragment
        ):
            raise ValueError(
                f"allowed_origins entries must be HTTP(S) origins without credentials or paths: "
                f"{value!r}"
            )
        result.add(_payment_origin(url))
    return frozenset(result)


def _should_inject(url: httpx.URL, policy: AcceptPaymentPolicy) -> bool:
    if policy == "always" or policy == "same-origin":
        # Outside browsers every request is same-origin for this purpose.
        return True
    if policy == "never":
        return False
    for pattern in policy:
        if pattern.startswith("*."):
            if url.host.endswith(pattern[1:]) or url.host == pattern[2:]:
                return True
        elif _origin(url) == _origin(httpx.URL(pattern)):
            return True
    return False


def _can_handle(method: ClientMethod, challenge: Challenge) -> bool:
    return method.can_handle_challenge is None or method.can_handle_challenge(challenge)


def _memoize(create: Callable[[Any], Awaitable[str]]) -> Callable[..., Awaitable[str]]:
    task: asyncio.Future[str] | None = None

    async def memoized(context: Any = None) -> str:
        nonlocal task
        if task is None:
            task = asyncio.ensure_future(create(context))
        return await asyncio.shield(task)

    return memoized


def _parse_context(method: ClientMethod, context: Any) -> Any:
    if method.context is None or context is None:
        return None
    return method.context.model_validate(context)


class _Tee:
    """Shares one response stream between the caller and an observer copy (``Response.clone``).

    Whichever branch reads first pulls the next chunk from the source and queues it for the
    other branch, so neither branch waits for the other.
    """

    def __init__(self, source: Any) -> None:
        self._source = source
        self._iterator = source.__aiter__()
        self._buffers: tuple[list[bytes], list[bytes]] = ([], [])
        self._done = False
        self._lock = asyncio.Lock()

    async def _next(self, branch: int) -> bytes | None:
        async with self._lock:
            if self._buffers[branch]:
                return self._buffers[branch].pop(0)
            if self._done:
                return None
            try:
                chunk = await self._iterator.__anext__()
            except StopAsyncIteration:
                self._done = True
                return None
            self._buffers[1 - branch].append(chunk)
            return chunk

    def branch(self, index: int) -> httpx.AsyncByteStream:
        tee = self

        class Branch(httpx.AsyncByteStream):
            async def __aiter__(self) -> AsyncIterator[bytes]:
                while (chunk := await tee._next(index)) is not None:
                    yield chunk

            async def aclose(self) -> None:
                if index == 0:
                    close = getattr(tee._source, "aclose", None)
                    if close is not None:
                        await close()

        return Branch()


def _tee(response: httpx.Response) -> httpx.Response:
    """Returns a readable copy of ``response`` without consuming the caller's stream."""
    try:
        content = response.content
    except httpx.ResponseNotRead:
        tee = _Tee(response.stream)
        response.stream = tee.branch(0)
        copy = httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=tee.branch(1),
            extensions=dict(response.extensions),
        )
    else:
        copy = httpx.Response(
            response.status_code,
            headers=response.headers,
            content=content,
            extensions=dict(response.extensions),
        )
    with contextlib.suppress(RuntimeError):
        copy.request = response.request
    return copy


def _bodyless(response: httpx.Response) -> httpx.Response:
    snapshot = httpx.Response(
        response.status_code, headers=response.headers, extensions=dict(response.extensions)
    )
    with contextlib.suppress(RuntimeError):
        snapshot.request = response.request
    return snapshot


@dataclass(slots=True)
class _PreparedCredential:
    attempt: Attempt
    method: ClientMethod
    task: "asyncio.Future[str]"
    key: str | None = None


async def _settle(prepared: _PreparedCredential | None, outcome: AttemptOutcome) -> bool:
    if prepared is None or prepared.attempt.settle is None:
        return outcome.status != "pending"
    settle = prepared.attempt.settle
    prepared.attempt.settle = None
    settled = bool(await resolve(settle(outcome)))
    if not settled:
        prepared.attempt.settle = settle
    return settled


async def _buffer_error_body(response: httpx.Response) -> httpx.Response:
    """Buffers a paid-retry error body within 64 KiB / 2 s so its connection is released.

    A complete body is kept unchanged; a larger or slower one is cut off and marked with
    ``Mppx-Body-Truncated: true``.
    """
    chunks: list[bytes] = []
    received = 0
    truncated = False
    try:
        async with asyncio.timeout(ERROR_BODY_TIMEOUT_SECONDS):
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                received += len(chunk)
                if received > MAX_ERROR_BODY_BYTES:
                    truncated = True
                    break
    except TimeoutError:
        truncated = True
    await response.aclose()
    headers = httpx.Headers(response.headers)
    # The buffered bytes are decoded, so transfer metadata of the encoded body no longer applies.
    if truncated or "content-encoding" in headers:
        headers.pop("content-length", None)
        headers.pop("content-encoding", None)
    if truncated:
        headers[BODY_TRUNCATED_HEADER] = "true"
    replay = httpx.Response(
        response.status_code,
        headers=headers,
        content=b"".join(chunks)[:MAX_ERROR_BODY_BYTES] if truncated else b"".join(chunks),
        extensions=dict(response.extensions),
    )
    with contextlib.suppress(RuntimeError):
        replay.request = response.request
    return replay


@dataclass(frozen=True, slots=True, kw_only=True)
class PreparedPayment:
    """A selected payment that can be inspected before its credential is created."""

    challenge: Challenge
    challenges: tuple[Challenge, ...]
    method: ClientMethod
    create_credential: Callable[..., Awaitable[str]] = field(repr=False)
    """Creates the selected challenge's credential (at most once)."""
    _transport: ClientTransport[Any, Any] = field(repr=False)

    def set_credential(self, request: Any, credential: str) -> Any:
        """Attaches a credential using the protocol that produced the selected challenge."""
        validate_credential_header_value(credential)
        return self._transport.set_credential(request, credential, self.challenge)


@dataclass(frozen=True, slots=True)
class Redirect:
    """A redirect followed while discovering a payment challenge."""

    from_url: str
    status: int
    to_url: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PreparedRequestPayment:
    """A request-bound payment: inspect it, create its credential, or ``pay()``."""

    prepared: PreparedPayment
    create_credential: Callable[..., Awaitable[str]] = field(repr=False)
    pay: Callable[..., Awaitable[httpx.Response]] = field(repr=False)
    """Creates and sends the credential to the prepared request without following redirects."""

    @property
    def challenge(self) -> Challenge:
        return self.prepared.challenge

    @property
    def challenges(self) -> tuple[Challenge, ...]:
        return self.prepared.challenges

    @property
    def method(self) -> ClientMethod:
        return self.prepared.method

    def set_credential(self, request: Any, credential: str) -> Any:
        return self.prepared.set_credential(request, credential)


@dataclass(frozen=True, slots=True, kw_only=True)
class PreparedRequest:
    """An HTTP request prepared together with its response and optional payment."""

    request: httpx.Request
    """The exact request that produced ``response``."""
    response: httpx.Response
    redirects: tuple[Redirect, ...]
    payment: PreparedRequestPayment | None


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_BODY_HEADERS = (
    "content-encoding",
    "content-language",
    "content-length",
    "content-location",
    "content-type",
    "transfer-encoding",
)
_CROSS_ORIGIN_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "cookie2",
        "host",
        "payment-authorization",
        "payment-signature",
        "proxy-authorization",
        "x-payment",
    }
)


class Mpp:
    """Client-side payment handler.

    Args:
        methods: Client methods (nested sequences are flattened).
        transport: Client protocol transport (default :func:`mpp.client.http_transport`).
        inner: Underlying ``httpx`` transport (default ``httpx.AsyncHTTPTransport()``).
        on_challenge: Called when no ``challenge.received`` handler supplied a credential.
        max_payment_retries: Maximum payment rounds after the initial response.
        order_challenges: Filters/sorts supported challenge candidates.
        payment_preferences: Per-capability q-values keyed by ``"method/intent"`` (or a callback
            receiving a key tree); advertised via ``Accept-Payment``.
        accept_payment_policy: When to inject ``Accept-Payment``.
        allowed_origins: Exact HTTP(S) origins (``"https://api.example.com"``) whose challenges
            are paid automatically. A payment-required response from any other origin, including
            one reached through a redirect, is returned unchanged: no credential is created and
            no payment event is emitted. Origins compare scheme, host and port (default ports
            normalized); entries with paths, queries or credentials are rejected. An empty list
            disables automatic payment; ``None`` (default) pays any origin. A challenge's
            ``realm`` is not an authenticated origin and is not compared.

    There is no global ``fetch`` patching: use :meth:`fetch`, :meth:`client` or
    ``httpx.AsyncClient(transport=mppx.payment_transport)``.
    """

    def __init__(
        self,
        *,
        methods: Methods,
        transport: ClientTransport[Any, Any] | None = None,
        inner: httpx.AsyncBaseTransport | None = None,
        on_challenge: OnChallenge | None = None,
        max_payment_retries: int = DEFAULT_MAX_PAYMENT_RETRIES,
        order_challenges: OrderChallenges | None = None,
        payment_preferences: _accept_payment.Preferences | None = None,
        accept_payment_policy: AcceptPaymentPolicy = "always",
        allowed_origins: Sequence[str] | None = None,
    ) -> None:
        self.methods = _flatten(methods)
        self.allowed_origins = _allowed_origins(allowed_origins)
        self.transport: ClientTransport[Any, Any] = transport or HttpTransport()
        raw = inner or httpx.AsyncHTTPTransport()
        self._inner = raw
        self.raw_transport: httpx.AsyncBaseTransport = raw
        self.on_challenge = on_challenge
        self.max_payment_retries = max_payment_retries
        self.order_challenges = order_challenges
        self.accept_payment = _accept_payment.resolve(self.methods, payment_preferences)
        self.accept_payment_policy = accept_payment_policy
        self.events = ClientEventDispatcher()
        self.payment_transport = PaymentTransport(self)
        self._client: httpx.AsyncClient | None = None

    # -- lifecycle ----------------------------------------------------------------------------

    def client(self, **kwargs: Any) -> httpx.AsyncClient:
        """Creates an ``httpx.AsyncClient`` paying through this handler.

        Redirects are followed like ``fetch``: before payment only. A redirect answering a
        credential-bearing request is returned to the caller unfollowed (mppx sends the paid
        retry with ``redirect: "manual"``).
        """
        kwargs.setdefault("follow_redirects", True)
        return PaymentClient(transport=self.payment_transport, **kwargs)

    async def fetch(
        self,
        url: str | httpx.URL,
        *,
        method: str = "GET",
        context: Any = None,
        order_challenges: OrderChallenges | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Sends a request, paying 402 challenges automatically; returns the read response.

        Extra keyword arguments are forwarded to ``httpx.AsyncClient.request``. Like ``fetch``,
        no timeout is applied unless ``timeout=`` is passed (paid requests may wait for
        settlement).
        """
        if self._client is None:
            self._client = self.client(timeout=None)
        extensions = dict(kwargs.pop("extensions", None) or {})
        if context is not None:
            extensions[CONTEXT_EXTENSION] = context
        if order_challenges is not None:
            extensions[ORDER_CHALLENGES_EXTENSION] = order_challenges
        return await self._client.request(method, url, extensions=extensions, **kwargs)

    async def aclose(self) -> None:
        """Closes the underlying transports."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        else:
            await self.raw_transport.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    # -- events -------------------------------------------------------------------------------

    def on(self, name: str, handler: Callable[[Any], Any]) -> Unsubscribe:
        """Registers a handler for ``challenge.received`` (may return a credential),
        ``credential.created``, ``payment.response``, ``payment.failed`` or ``"*"``."""
        return self.events.on(name, handler)

    def on_challenge_received(self, handler: Callable[[Any], Any]) -> Unsubscribe:
        return self.events.on("challenge.received", handler)

    def on_credential_created(self, handler: Callable[[Any], Any]) -> Unsubscribe:
        return self.events.on("credential.created", handler)

    def on_payment_failed(self, handler: Callable[[Any], Any]) -> Unsubscribe:
        return self.events.on("payment.failed", handler)

    def on_payment_response(self, handler: Callable[[Any], Any]) -> Unsubscribe:
        return self.events.on("payment.response", handler)

    # -- selection ----------------------------------------------------------------------------

    def _preferences(
        self, override: str | Sequence[_accept_payment.Entry] | None
    ) -> Sequence[_accept_payment.Entry]:
        if not override:
            return self.accept_payment.entries
        return _accept_payment.parse(override) if isinstance(override, str) else override

    async def _candidates(
        self,
        challenges: Sequence[Challenge],
        preferences: Sequence[_accept_payment.Entry],
        order: OrderChallenges | None,
    ) -> Sequence[ChallengeCandidate]:
        candidates = _accept_payment.select_challenge_candidates(
            challenges, self.methods, preferences, _can_handle
        )
        hook = order or self.order_challenges
        return await resolve(hook(candidates)) if hook is not None else candidates

    async def _create(
        self,
        challenge: Challenge,
        method: ClientMethod,
        context: Any,
        attempt: Attempt | None = None,
    ) -> str:
        params = CredentialParams(
            challenge=challenge,
            context=_parse_context(method, context),
            attempt=attempt if method.handle_response is not None else None,
        )
        return await method.create_credential(params)

    # -- manual flows -------------------------------------------------------------------------

    async def prepare_payment(
        self,
        response: Any,
        *,
        request: Any = None,
        accept_payment: str | Sequence[_accept_payment.Entry] | None = None,
        order_challenges: OrderChallenges | None = None,
    ) -> PreparedPayment:
        """Selects a payment challenge from ``response`` without creating its credential.

        Raises:
            ValueError: When no configured method can pay the offered challenges.
        """
        challenges: tuple[Challenge, ...] = ()
        challenge: Challenge | None = None
        method: ClientMethod | None = None
        try:
            challenges = tuple(await self.transport.get_challenges(response, request))
            candidates = await self._candidates(
                challenges, self._preferences(accept_payment), order_challenges
            )
            if not candidates:
                raise ValueError(_no_method_message(challenges, self.methods))
            selected = candidates[0]
            challenge, method = selected.challenge, selected.method
            if challenge.expires:
                _expires.ensure(challenge.expires, challenge.id)
        except Exception as error:
            await self.events.emit(
                "payment.failed",
                ClientPaymentFailed(
                    challenge=challenge,
                    challenges=challenges or None,
                    error=error,
                    method=method,
                    response=response,
                ),
            )
            raise
        selected_challenge, selected_method = challenge, method
        events = self.events

        async def create(context: Any = None) -> str:
            try:
                if selected_challenge.expires:
                    _expires.ensure(selected_challenge.expires, selected_challenge.id)
                inner = _memoize(
                    lambda override: self._create(
                        selected_challenge,
                        selected_method,
                        override if override is not None else context,
                    )
                )
                credential = (
                    await events.emit(
                        "challenge.received",
                        ChallengeReceived(
                            challenge=selected_challenge,
                            challenges=challenges,
                            create_credential=inner,
                            method=selected_method,
                            response=response,
                        ),
                    )
                    or await inner()
                )
                validate_credential_header_value(credential)
                await events.emit(
                    "credential.created",
                    CredentialCreated(
                        challenge=selected_challenge,
                        credential=credential,
                        method=selected_method,
                        response=response,
                    ),
                )
                return credential
            except Exception as error:
                await events.emit(
                    "payment.failed",
                    ClientPaymentFailed(
                        challenge=selected_challenge,
                        challenges=challenges,
                        error=error,
                        method=selected_method,
                        response=response,
                    ),
                )
                raise

        return PreparedPayment(
            challenge=selected_challenge,
            challenges=challenges,
            method=selected_method,
            create_credential=_memoize(create),
            _transport=self.transport,
        )

    async def create_credential(
        self,
        response: Any,
        context: Any = None,
        *,
        request: Any = None,
        accept_payment: str | Sequence[_accept_payment.Entry] | None = None,
        order_challenges: OrderChallenges | None = None,
    ) -> str:
        """Creates a credential from a payment-required response."""
        prepared = await self.prepare_payment(
            response,
            request=request,
            accept_payment=accept_payment,
            order_challenges=order_challenges,
        )
        return await prepared.create_credential(context)

    async def prepare_request(
        self,
        url: str | httpx.URL,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | httpx.Headers | None = None,
        content: bytes | str | None = None,
        max_redirects: int = 20,
        require_payment: bool = False,
        accept_payment: str | Sequence[_accept_payment.Entry] | None = None,
        order_challenges: OrderChallenges | None = None,
    ) -> PreparedRequest:
        """Follows safe pre-payment redirects and returns the response with its exact request.

        When payment is required the selected challenge is prepared (no credential yet).
        Credential-bearing requests never follow redirects.

        Raises:
            ValueError: On invalid ``max_redirects``, HTTPS downgrades, too many redirects, or
                when ``require_payment`` is set and no payment is required.
        """
        if max_redirects < 0:
            raise ValueError("maxRedirects must be a non-negative integer.")
        request = httpx.Request(method, url, headers=headers, content=content)
        explicit = Header.ACCEPT_PAYMENT in request.headers
        body = request.content or None
        redirects: list[Redirect] = []
        while True:
            request = self._with_accept_payment(request, explicit)
            response = await self._inner.handle_async_request(request)
            response.request = request
            if response.status_code not in _REDIRECT_STATUSES or "location" not in response.headers:
                break
            if len(redirects) >= max_redirects:
                await response.aclose()
                raise ValueError(f"Payment request exceeded {max_redirects} redirects.")
            source = request.url
            target = source.join(response.headers["location"])
            if source.scheme == "https" and target.scheme != "https":
                await response.aclose()
                raise ValueError(f"Payment request refused HTTPS downgrade redirect to {target}")
            next_request = _redirect_request(request, response, target, body)
            body = next_request.content or None
            redirects.append(Redirect(str(source), response.status_code, str(target)))
            await response.aclose()
            request = next_request

        payable = self._pays_origin(request.url)
        if not payable or not await self.transport.is_payment_required(response, request):
            if require_payment:
                raise ValueError(
                    "Response does not require payment."
                    if payable
                    else f"Payment origin is not allowed: {_origin(request.url)}"
                )
            return PreparedRequest(
                request=request, response=response, redirects=tuple(redirects), payment=None
            )
        prepared = await self.prepare_payment(
            response,
            request=request,
            accept_payment=accept_payment,
            order_challenges=order_challenges,
        )
        final_request = request
        raw = self.raw_transport

        async def create(context: Any = None) -> str:
            if prepared.method.prepare is not None:
                await resolve(
                    prepared.method.prepare(
                        PrepareParams(
                            challenge=prepared.challenge,
                            context=context,
                            send=raw.handle_async_request,
                            request=final_request,
                        )
                    )
                )
            return await prepared.create_credential(context)

        create_once = _memoize(create)

        async def pay(context: Any = None) -> httpx.Response:
            credential = await create_once(context)
            paid = prepared.set_credential(rebuild_request(final_request), credential)
            paid_response = await raw.handle_async_request(paid)
            paid_response.request = paid
            return paid_response

        return PreparedRequest(
            request=request,
            response=response,
            redirects=tuple(redirects),
            payment=PreparedRequestPayment(
                prepared=prepared, create_credential=create_once, pay=pay
            ),
        )

    def _pays_origin(self, url: str | httpx.URL) -> bool:
        """Whether challenges served from ``url``'s origin may be paid (``allowed_origins``)."""
        return self.allowed_origins is None or (
            _payment_origin(httpx.URL(url)) in self.allowed_origins
        )

    def _with_accept_payment(self, request: httpx.Request, explicit: bool) -> httpx.Request:
        if explicit:
            return request
        headers = httpx.Headers(request.headers)
        headers.pop(Header.ACCEPT_PAYMENT, None)
        if self.accept_payment.header and _should_inject(request.url, self.accept_payment_policy):
            headers[Header.ACCEPT_PAYMENT] = self.accept_payment.header
        return rebuild_request(request, headers=headers)


def _redirect_request(
    request: httpx.Request, response: httpx.Response, target: httpx.URL, body: bytes | None
) -> httpx.Request:
    """Builds the next hop of a redirect like WHATWG fetch (method switch, header stripping)."""
    headers = httpx.Headers(request.headers)
    method = request.method
    if (response.status_code in (301, 302) and method == "POST") or (
        response.status_code == 303 and method not in ("GET", "HEAD")
    ):
        method = "GET"
        body = None
        for header in _BODY_HEADERS:
            headers.pop(header, None)
    if _origin(request.url) != _origin(target):
        for key in list(headers.keys()):
            value = headers.get(key) or ""
            if key.lower() in _CROSS_ORIGIN_HEADERS or value.startswith("Payment "):
                headers.pop(key, None)
    headers.pop("host", None)
    return httpx.Request(
        method, target, headers=headers, content=body, extensions=request.extensions
    )


def _no_method_message(challenges: Sequence[Challenge], methods: Sequence[ClientMethod]) -> str:
    offered = ", ".join(f"{c.method}.{c.intent}" for c in challenges)
    available = ", ".join(f"{m.name}.{m.intent}" for m in methods)
    return f"No method found for challenges: {offered}. Available: {available}"


def _paid(request: httpx.Request) -> bool:
    """Whether this very request object carried a payment credential on its last send."""
    return request.extensions.get(_PAID_EXTENSION) is request


class PaymentClient(httpx.AsyncClient):
    """``httpx.AsyncClient`` that never follows a redirect answering a paid request."""

    async def send(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
        auth: Any = httpx.USE_CLIENT_DEFAULT,
        follow_redirects: Any = httpx.USE_CLIENT_DEFAULT,
    ) -> httpx.Response:
        follow = (
            self.follow_redirects
            if follow_redirects is httpx.USE_CLIENT_DEFAULT
            else bool(follow_redirects)
        )
        history: list[httpx.Response] = []
        for _ in range(self.max_redirects + 1):
            response = await super().send(request, stream=stream, auth=auth, follow_redirects=False)
            location = response.headers.get("location")
            if (
                not follow
                or response.status_code not in _REDIRECT_STATUSES
                or location is None
                or _paid(request)
            ):
                response.history = history
                return response
            await response.aclose()
            history.append(response)
            request = _redirect_request(
                request, response, request.url.join(location), request.content or None
            )
            request.extensions = {
                k: v for k, v in request.extensions.items() if k != _PAID_EXTENSION
            }
        raise httpx.TooManyRedirects("Exceeded maximum allowed redirects.", request=request)


class PaymentTransport(httpx.AsyncBaseTransport):
    """An ``httpx`` transport that pays 402 challenges automatically.

    Per-request options travel as request extensions: ``"mpp.context"`` (credential context)
    and ``"mpp.order_challenges"``.
    """

    def __init__(self, mppx: Mpp) -> None:
        self._mppx = mppx

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._request(request, can_refetch=True)

    async def aclose(self) -> None:
        await self._mppx.raw_transport.aclose()

    async def _send(self, request: httpx.Request) -> httpx.Response:
        response = await self._mppx.raw_transport.handle_async_request(request)
        response.request = request
        return response

    async def _request(self, request: httpx.Request, *, can_refetch: bool) -> httpx.Response:
        mppx = self._mppx
        transport = mppx.transport
        events = mppx.events
        await request.aread()
        origin = request.extensions.setdefault(_ORIGIN_EXTENSION, _origin(request.url))

        explicit = request.headers.get(Header.ACCEPT_PAYMENT)
        entries = mppx.accept_payment.entries
        header = mppx.accept_payment.header
        if explicit is not None:
            # Fail open: keep the caller's header on the wire but select with defaults.
            with contextlib.suppress(ValueError):
                entries, header = _accept_payment.parse(explicit), explicit
        initial = request
        if header and explicit is None and _should_inject(request.url, mppx.accept_payment_policy):
            headers = httpx.Headers(request.headers)
            headers[Header.ACCEPT_PAYMENT] = header
            initial = rebuild_request(request, headers=headers)

        paid_by = request.extensions.get(_PAID_EXTENSION)
        if paid_by is request:
            # The same request object is being sent again: negotiate and pay afresh.
            del request.extensions[_PAID_EXTENSION]
        response = await self._send(initial)
        if paid_by is not None and paid_by is not request:
            # A redirect hop derived from a paid request is never paid again automatically.
            return response
        if not mppx._pays_origin(initial.url):
            # Never pay a challenge served by an origin outside ``allowed_origins``.
            return response
        if not await transport.is_payment_required(response, initial):
            return response

        context = request.extensions.get(CONTEXT_EXTENSION)
        order = request.extensions.get(ORDER_CHALLENGES_EXTENSION)
        challenge: Challenge | None = None
        challenges: tuple[Challenge, ...] | None = None
        selected_method: ClientMethod | None = None
        prepared: _PreparedCredential | None = None
        outcome_unknown: PaymentOutcomeUnknownError | None = None

        try:
            for retry in range(mppx.max_payment_retries):
                challenges = tuple(await transport.get_challenges(response, initial))
                candidates = await mppx._candidates(challenges, entries, order)
                if not candidates:
                    await _settle(
                        prepared,
                        AttemptOutcome(status="rejected", challenges=challenges, response=response),
                    )
                    # A post-payment 402 without an actionable challenge is the final answer.
                    if retry > 0:
                        return response
                    raise ValueError(_no_method_message(challenges, mppx.methods))

                selected = candidates[0]
                current_challenge = selected.challenge
                current_method = selected.method
                challenge, selected_method = current_challenge, current_method
                if current_challenge.expires:
                    _expires.ensure(current_challenge.expires, current_challenge.id)

                current_origin = _origin(initial.url)
                if current_origin != origin:
                    raise ValueError(
                        f"Refusing to send payment credential across redirect from {origin} "
                        f"to {current_origin}"
                    )

                previous = prepared
                key = current_challenge.serialize()
                same_attempt = (
                    previous is not None
                    and previous.method is current_method
                    and previous.key == key
                )
                reuse = False
                if previous is not None:
                    settled = await _settle(
                        previous,
                        AttemptOutcome(
                            status="pending" if same_attempt else "rejected",
                            challenges=challenges,
                            response=response,
                        ),
                    )
                    reuse = same_attempt and not settled
                prepared = previous if reuse else None
                state: dict[str, Any] = {"prepared": prepared}

                async def create_credential(
                    override: Any = None,
                    *,
                    _challenge: Challenge = current_challenge,
                    _method: ClientMethod = current_method,
                    _previous: _PreparedCredential | None = previous,
                    _reuse: bool = reuse,
                    _key: str = key,
                    _state: dict[str, Any] = state,
                ) -> str:
                    if override is None and _reuse and _previous is not None:
                        return await asyncio.shield(_previous.task)
                    if _reuse and _previous is not None:
                        await _settle(_previous, AttemptOutcome(status="rejected"))
                        _state["prepared"] = None
                    credential_context = override if override is not None else context
                    if _method.prepare is None:
                        return await mppx._create(_challenge, _method, credential_context)

                    async def prepare() -> None:
                        assert _method.prepare is not None
                        await resolve(
                            _method.prepare(
                                PrepareParams(
                                    challenge=_challenge,
                                    context=credential_context,
                                    send=self._send,
                                    request=initial,
                                )
                            )
                        )

                    attempt = Attempt(prepare=prepare)

                    async def run() -> str:
                        await attempt.prepare()
                        return await mppx._create(_challenge, _method, credential_context, attempt)

                    task = asyncio.ensure_future(run())
                    _state["prepared"] = _PreparedCredential(
                        attempt=attempt,
                        method=_method,
                        task=task,
                        key=_key if override is None else None,
                    )
                    return await asyncio.shield(task)

                memoized = _memoize(create_credential)
                event_credential = await events.emit(
                    "challenge.received",
                    ChallengeReceived(
                        challenge=current_challenge,
                        challenges=challenges,
                        create_credential=memoized,
                        method=current_method,
                        response=response,
                        request=request,
                    ),
                )
                credential = event_credential
                if credential is None and mppx.on_challenge is not None:
                    credential = await mppx.on_challenge(current_challenge, memoized)
                if credential is None:
                    credential = await memoized()
                prepared = state["prepared"]
                if prepared is not None:
                    try:
                        prepared_credential = await asyncio.shield(prepared.task)
                    except Exception:
                        prepared_credential = None
                    if prepared_credential != credential:
                        await _settle(prepared, AttemptOutcome(status="rejected"))
                        prepared = None
                validate_credential_header_value(credential)
                await events.emit(
                    "credential.created",
                    CredentialCreated(
                        challenge=current_challenge,
                        credential=credential,
                        method=current_method,
                        response=response,
                        request=request,
                    ),
                )

                def unknown(
                    cause: BaseException | None = None,
                    *,
                    _challenge: Challenge = current_challenge,
                    _credential: str = credential,
                    _method: ClientMethod = current_method,
                ) -> PaymentOutcomeUnknownError:
                    transaction_hash = None
                    if _method.transaction_hash is not None:
                        try:
                            transaction_hash = _method.transaction_hash(_credential)
                        except Exception:
                            transaction_hash = None
                    return PaymentOutcomeUnknownError(
                        challenge=_challenge,
                        credential=_credential,
                        transaction_hash=transaction_hash,
                        cause=cause,
                    )

                paid_request = transport.set_credential(
                    rebuild_request(initial), credential, current_challenge
                )
                # Release the challenge response's connection before the paid retry.
                await response.aclose()
                try:
                    response = await self._send(paid_request)
                except (Exception, asyncio.CancelledError) as cause:
                    outcome_unknown = unknown(cause)
                    raise
                payment_required = await transport.is_payment_required(response, initial)
                if not payment_required:
                    await _settle(
                        prepared,
                        AttemptOutcome(
                            status=(
                                "pending"
                                if 300 <= response.status_code < 400
                                else "accepted"
                                if response.is_success
                                else "rejected"
                            ),
                            response=response,
                        ),
                    )
                    prepared = None
                    request.extensions[_PAID_EXTENSION] = request
                if response.is_success and events.has_observers("payment.response"):
                    await events.emit(
                        "payment.response",
                        PaymentResponse(
                            challenge=current_challenge,
                            credential=credential,
                            method=current_method,
                            response=_tee(response),
                            request=request,
                        ),
                    )
                if not payment_required:
                    # The server may have settled before failing: report the credential for
                    # reconciliation and return the response. Retrying could pay twice.
                    if response.status_code >= 500 and events.has_observers("payment.failed"):
                        try:
                            response = await _buffer_error_body(response)
                        except Exception as cause:
                            outcome_unknown = unknown(cause)
                            response = _bodyless(response)
                            raise
                        await events.emit(
                            "payment.failed",
                            ClientPaymentFailed(
                                challenge=current_challenge,
                                challenges=challenges,
                                error=unknown(),
                                method=current_method,
                                response=response,
                                request=request,
                            ),
                        )
                    if not response.is_success:
                        return response
                    if current_method.handle_response is None:
                        return response

                    async def refetch() -> httpx.Response:
                        fresh = rebuild_request(request)
                        fresh.extensions = {
                            key: value
                            for key, value in request.extensions.items()
                            if key != _PAID_EXTENSION
                        }
                        return await self._request(fresh, can_refetch=False)

                    return await resolve(
                        current_method.handle_response(
                            ResponseParams(
                                challenge=current_challenge,
                                credential=credential,
                                send=self._send,
                                headers=initial.headers,
                                request=paid_request,
                                response=response,
                                refetch=refetch if can_refetch else None,
                            )
                        )
                    )
            final_challenges: tuple[Challenge, ...] | None = None
            try:
                final_challenges = tuple(await transport.get_challenges(response, initial))
            except Exception:
                final_challenges = None
            await _settle(
                prepared,
                AttemptOutcome(status="rejected", challenges=final_challenges, response=response),
            )
            return response
        except (Exception, asyncio.CancelledError) as error:
            # Cancellation after the credential was sent still needs reconciliation.
            await _settle(
                prepared,
                AttemptOutcome(status="rejected", challenges=challenges, response=response),
            )
            await events.emit(
                "payment.failed",
                ClientPaymentFailed(
                    challenge=challenge,
                    challenges=challenges,
                    error=outcome_unknown or error,
                    method=selected_method,
                    response=response,
                    request=request,
                ),
            )
            # The caller never receives this response, so release its connection.
            await asyncio.shield(response.aclose())
            raise
