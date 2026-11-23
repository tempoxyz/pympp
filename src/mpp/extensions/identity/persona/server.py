"""Persona KYC on the server: start inquiries and require an approved one (mppx `Persona.Server`).

:func:`create` returns a :class:`Persona` client for one Persona organization and inquiry
template:

- :meth:`Persona.start_inquiry` starts an inquiry for a reference ID and returns a one-time
  link to Persona's hosted flow.
- :meth:`Persona.payment_check` requires an approved inquiry on a route's paid retry, keyed by
  the payer.
- :meth:`Persona.verifier` requires one before any 402, keyed by your own session.

Link a wallet to a person by proving they own it (:func:`verify_wallet`) before you start an
inquiry with its DID as the reference ID. Otherwise anyone can complete KYC as themselves for
someone else's wallet.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import math
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, TypeAlias, TypeVar, cast
from urllib.parse import quote

import anyio
import httpx

from mpp.extensions.identity.persona import (
    API_URL,
    API_VERSION,
    CACHE_TTL,
    INQUIRIES_PATH,
    ISSUER,
    MAX_PAGES,
    REL,
    STATUSES,
    TIMEOUT,
    TYPE,
    InquiryStatus,
    StartedInquiry,
    VerifiedInquiry,
    did,
)
from mpp.identity import (
    HeaderPairs,
    PaymentCheck,
    PaymentCheckInput,
    Requirement,
    Valid,
    Verification,
    Verifier,
    _origin,  # pyright: ignore[reportPrivateUsage]
    forbidden,
    missing,
    unavailable,
)

if TYPE_CHECKING:
    from mpp.server.http import Request
    from mpp.store import Store

T = TypeVar("T")

PaymentReferenceId: TypeAlias = "Callable[[PaymentCheckInput], str | None | Awaitable[str | None]]"
"""Returns the payer's authenticated reference ID on the paid retry, or None when there is none."""
RequestReferenceId: TypeAlias = "Callable[[Request], str | None | Awaitable[str | None]]"
"""Returns the caller's reference ID from the request, or None when there is none."""
Onboarding: TypeAlias = "str | Callable[[Request, str | None], str | None | Awaitable[str | None]]"
"""Where a rejected payer starts KYC: a URL, or a function of the request and reference ID."""

_MALFORMED = "The Persona API response is malformed."
# mppx bounds its millisecond timeout by 2^31 - 1, the longest delay a JavaScript timer holds.
_MAX_TIMEOUT = 2_147_483.647
_PAGE_SIZE = "25"
# encodeURIComponent's unreserved characters.
_PATH_SAFE = "-_.!~*'()"


class PersonaError(Exception):
    """A failed or malformed Persona API call. It never carries the upstream body."""


class WalletVerifier(Protocol):
    """Checks that ``signature`` over ``message`` is from ``address`` on ``chain_id``."""

    def __call__(
        self, *, address: str, chain_id: int, message: str, signature: str
    ) -> bool | Awaitable[bool]: ...


def create(
    *,
    api_key: str,
    template_id: str | None = None,
    api_url: str = API_URL,
    api_version: str = API_VERSION,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = TIMEOUT,
) -> Persona:
    """Create a Persona client for one Persona organization and inquiry template.

    Args:
        api_key: Persona API key. Keep it on the server.
        template_id: Inquiry template (``itmpl_...``) to start inquiries from and accept them
            from.
        api_url: Persona API origin.
        api_version: The ``Persona-Version`` header.
        transport: httpx transport for the Persona API. A payment-aware
            :class:`mpp.client.PaymentTransport` is unwrapped to its inner transport, so a
            Persona call never pays a Challenge.
        timeout: Seconds before a Persona API call is abandoned as ``unavailable``.

    Raises:
        ValueError: Without an API key, or with a timeout that is not a positive number of
            seconds up to about 24 days.

    Example::

        persona = create(api_key=os.environ["PERSONA_API_KEY"], template_id="itmpl_...")
        kyc = persona.payment_check(
            reference_id=lambda input: session_wallet(input.request),
            onboarding="https://api.example/kyc",
            cache=MemoryStore(),
        )
        mpp.charge(amount="1", identity=identity.Route(payment=kyc))
    """
    if not api_key:
        raise ValueError("persona.server.create needs an api_key.")
    value = cast("object", timeout)
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or not 0 < value <= _MAX_TIMEOUT
    ):
        raise ValueError("persona.server.create needs a positive timeout in seconds.")
    api = _Api(
        api_key=api_key,
        api_url=api_url,
        api_version=api_version,
        transport=transport,
        timeout=float(value),
    )
    return Persona(api, template_id)


@dataclass(frozen=True, slots=True)
class _LookupOptions:
    statuses: tuple[InquiryStatus, ...]
    max_age: int | None
    onboarding: Onboarding | None
    cache: Store | None
    cache_ttl: float


class Persona:
    """A Persona client from :func:`create`."""

    __slots__ = ("_api", "_scope", "_template_id")

    def __init__(self, api: _Api, template_id: str | None) -> None:
        self._api = api
        self._template_id = template_id
        # A digest of the API origin and key: names the Persona organization without the key.
        digest = hashlib.sha256(f"{_origin(api.api_url)}\n{api.api_key}".encode()).digest()
        self._scope = digest[:16].hex()

    async def start_inquiry(
        self,
        reference_id: str,
        *,
        template_id: str | None = None,
        redirect_uri: str | None = None,
    ) -> StartedInquiry:
        """Start an inquiry for a reference ID and return a one-time link to Persona's flow.

        Args:
            reference_id: Reference ID to match later, such as
                :func:`~mpp.extensions.identity.persona.did` of a wallet the person proved
                they own.
            template_id: Inquiry template, overriding the client's.
            redirect_uri: Where Persona sends the person after the flow.

        Raises:
            ValueError: Without a reference ID or an inquiry template.
            PersonaError: When the Persona API fails or answers malformed.
        """
        inquiry_template_id = template_id if template_id is not None else self._template_id
        if not reference_id:
            raise ValueError("start_inquiry needs a reference_id.")
        if not inquiry_template_id:
            raise ValueError("start_inquiry needs a template_id.")
        attributes = {"inquiry-template-id": inquiry_template_id, "reference-id": reference_id}
        if redirect_uri:
            attributes["redirect-uri"] = redirect_uri
        created = await self._api.call(
            self._api.url(INQUIRIES_PATH), method="POST", body={"data": {"attributes": attributes}}
        )
        inquiry_id = _dict(_dict(created).get("data")).get("id")
        if not isinstance(inquiry_id, str):
            raise PersonaError(_MALFORMED)
        path = f"{INQUIRIES_PATH}/{quote(inquiry_id, safe=_PATH_SAFE)}/generate-one-time-link"
        link = await self._api.call(self._api.url(path), method="POST", body={})
        url = _dict(_dict(link).get("meta")).get("one-time-link")
        if not isinstance(url, str):
            raise PersonaError(_MALFORMED)
        return StartedInquiry(inquiry_id=inquiry_id, url=url)

    def payment_check(
        self,
        *,
        reference_id: PaymentReferenceId,
        statuses: Sequence[InquiryStatus] = STATUSES,
        max_age: int | None = None,
        onboarding: Onboarding | None = None,
        cache: Store | None = None,
        cache_ttl: float = CACHE_TTL,
    ) -> PaymentCheck[VerifiedInquiry]:
        """Return a payment check that requires the payer to have passed Persona KYC.

        Every 402 of the route lists
        ``Identity-Required: kyc;issuer="https://api.withpersona.com"``. On the paid retry,
        before the Credential settles, it accepts the most recent inquiry whose reference ID
        ``reference_id`` returns. Derive it from something your server authenticated, such as
        your own session, or a payer address your payment method verified: a Credential's
        ``source`` is client-supplied and some payment flows do not check it against the payer,
        so returning it as is lets a payer present another wallet's KYC.

        No payer is ``missing`` (401), no accepted inquiry ``forbidden`` (403), both with
        ``onboarding`` in a ``Link`` header; a Persona API failure is ``unavailable`` (503).

        Args:
            reference_id: Returns the payer's reference ID from the paid retry.
            statuses: Accepted inquiry statuses.
            max_age: Oldest accepted verification, in seconds since the inquiry was decisioned
                or completed.
            onboarding: Where a rejected payer starts KYC, sent as
                ``Link: <url>; rel="kyc"`` with 401 and 403 responses, such as your endpoint
                that calls :meth:`start_inquiry`.
            cache: Caches approvals by reference ID, so a paid request skips the Persona API.
            cache_ttl: Seconds an approval stays cached.

        Raises:
            ValueError: With no statuses, a ``max_age`` that is not a positive integer, or a
                negative ``cache_ttl``.
        """
        options = _options(statuses, max_age, onboarding, cache, cache_ttl)

        async def verify(input: PaymentCheckInput) -> Verification[VerifiedInquiry]:
            return await self._lookup(await _resolve(reference_id(input)), options, input.request)

        return PaymentCheck(requires=(Requirement(type=TYPE, issuer=ISSUER),), verify=verify)

    def verifier(
        self,
        *,
        reference_id: RequestReferenceId,
        statuses: Sequence[InquiryStatus] = STATUSES,
        max_age: int | None = None,
        onboarding: Onboarding | None = None,
        cache: Store | None = None,
        cache_ttl: float = CACHE_TTL,
    ) -> Verifier[VerifiedInquiry]:
        """Return a request verifier that requires an approved inquiry before any 402.

        ``reference_id`` identifies the caller from the request, such as by your own session.
        The other options are :meth:`payment_check`'s.

        Raises:
            ValueError: As :meth:`payment_check` does.
        """
        options = _options(statuses, max_age, onboarding, cache, cache_ttl)

        async def verify(request: Request) -> Verification[VerifiedInquiry]:
            return await self._lookup(await _resolve(reference_id(request)), options, request)

        return Verifier(verify=verify)

    async def _lookup(
        self, reference_id: str | None, options: _LookupOptions, request: Request
    ) -> Verification[VerifiedInquiry]:
        """Look a reference ID up, through the cache when set, and map it to a verification."""
        headers = await _onboarding_headers(options.onboarding, request, reference_id)
        if not reference_id:
            return missing("Persona KYC requires a payer.", headers)

        # Scoped to the Persona organization and environment, so clients sharing a Store never
        # accept each other's approvals.
        key = f"mppx:persona:{self._scope}:{self._template_id or ''}:{reference_id}"
        now = time.time()
        if options.cache is not None:
            cached = _CacheEntry.read(await options.cache.get(key))
            if (
                cached is not None
                # Each check applies its own lifetime, so a longer-lived check sharing the Store
                # never extends a stricter one's revalidation window.
                and cached.cached_at + options.cache_ttl * 1000 > now * 1000
                and cached.status in options.statuses
                and _fresh(cached.verified_at, options.max_age, now)
            ):
                return Valid(
                    VerifiedInquiry(
                        inquiry_id=cached.inquiry_id,
                        reference_id=reference_id,
                        status=cached.status,
                        verified_at=cached.verified_at,
                    )
                )

        try:
            inquiry = await self._find(reference_id, options.statuses, options.max_age)
        except Exception:
            return unavailable("Persona KYC verification is unavailable.")
        if inquiry is None:
            return forbidden("The payer has not passed Persona KYC.", headers)
        # Only approvals are cached, so a person who just passed KYC is never kept waiting.
        if options.cache is not None:
            entry = _CacheEntry(
                cached_at=now * 1000,
                inquiry_id=inquiry.inquiry_id,
                status=inquiry.status,
                verified_at=inquiry.verified_at,
            )
            await options.cache.put(key, entry.dump())
        return Valid(inquiry)

    async def _find(
        self, reference_id: str, statuses: tuple[InquiryStatus, ...], max_age: int | None
    ) -> VerifiedInquiry | None:
        """Return the most recent accepted inquiry for a reference ID, or None."""
        params = {"filter[reference-id]": reference_id, "filter[status]": ",".join(statuses)}
        if self._template_id:
            params["filter[inquiry-template-id]"] = self._template_id
        params["page[size]"] = _PAGE_SIZE
        next_url: str | None = str(self._api.url(INQUIRIES_PATH).copy_merge_params(params))
        now = time.time()
        for _ in range(MAX_PAGES):
            if next_url is None:
                break
            body = _dict(await self._api.call(next_url))
            data: object = body.get("data")
            if not isinstance(data, list):
                raise PersonaError(_MALFORMED)
            # Persona lists the most recent inquiries first.
            for inquiry in cast("list[object]", data):
                accepted = self._accepted(inquiry, reference_id, statuses, max_age, now)
                if accepted is not None:
                    return accepted
            next_url = _same_origin(_dict(body.get("links")).get("next"), self._api.api_url)
        return None

    def _accepted(
        self,
        inquiry: object,
        reference_id: str,
        statuses: tuple[InquiryStatus, ...],
        max_age: int | None,
        now: float,
    ) -> VerifiedInquiry | None:
        fields = _dict(inquiry)
        inquiry_id = fields.get("id")
        attributes = _dict(fields.get("attributes"))
        if not isinstance(inquiry_id, str):
            return None
        # Recheck what the filters asked for, so an API or proxy that ignores them cannot
        # widen them.
        if attributes.get("reference-id") != reference_id:
            return None
        status = attributes.get("status")
        if status not in statuses:
            return None
        # Fails closed when the inquiry does not name its template.
        if self._template_id:
            template = _dict(_dict(fields.get("relationships")).get("inquiry-template"))
            if _dict(template.get("data")).get("id") != self._template_id:
                return None
        decisioned = attributes.get("decisioned-at")
        verified_at = _date(
            decisioned if decisioned is not None else attributes.get("completed-at")
        )
        if not _fresh(verified_at, max_age, now):
            return None
        return VerifiedInquiry(
            inquiry_id=inquiry_id,
            reference_id=reference_id,
            status=status,
            verified_at=verified_at,
        )


@dataclass(frozen=True, slots=True)
class _Api:
    """Calls one Persona organization's API with its key."""

    api_key: str
    api_url: str
    api_version: str
    transport: httpx.AsyncBaseTransport | None
    timeout: float

    def url(self, path: str) -> httpx.URL:
        return httpx.URL(self.api_url).join(path)

    async def call(self, url: httpx.URL | str, *, method: str = "GET", body: object = None) -> Any:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "Persona-Version": self.api_version,
        }
        content: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            content = json.dumps(body).encode()
        transport = _unwrapped(self.transport)
        # A whole-call deadline: httpx's own timeout applies to each phase separately.
        with anyio.fail_after(self.timeout):
            async with httpx.AsyncClient(
                transport=_Borrowed(transport) if transport is not None else None,
                # A redirect is a failure: never send the key on, nor read another origin's body.
                follow_redirects=False,
                timeout=self.timeout,
            ) as client:
                response = await client.request(method, url, headers=headers, content=content)
        # Never surface the upstream body: it may carry request details.
        if not response.is_success:
            raise PersonaError(f"The Persona API returned {response.status_code}.")
        try:
            return response.json()
        except ValueError:
            raise PersonaError(_MALFORMED) from None


class _Borrowed(httpx.AsyncBaseTransport):
    """A caller's transport, which closing the per-call client must leave open."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._inner.handle_async_request(request)


def _unwrapped(transport: httpx.AsyncBaseTransport | None) -> httpx.AsyncBaseTransport | None:
    """Unwrap mpp's payment-aware transport: a Persona request must never pay a Challenge."""
    # Without mpp.client loaded, no transport can be a PaymentTransport.
    if "mpp.client.transport" not in sys.modules:
        return transport
    from mpp.client.transport import PaymentTransport

    while isinstance(transport, PaymentTransport):
        transport = transport._inner  # pyright: ignore[reportPrivateUsage]
    return transport


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    """A cached approval, stored as mppx stores it (JSON, so Redis and SQL stores take it)."""

    cached_at: float
    inquiry_id: str
    status: InquiryStatus
    verified_at: datetime | None

    def dump(self) -> str:
        entry: dict[str, object] = {
            "cachedAt": int(self.cached_at),
            "inquiryId": self.inquiry_id,
            "status": self.status,
        }
        if self.verified_at is not None:
            entry["verifiedAt"] = _iso(self.verified_at)
        return json.dumps(entry)

    @classmethod
    def read(cls, value: object) -> _CacheEntry | None:
        if isinstance(value, str | bytes):
            try:
                value = json.loads(value)
            except ValueError:
                return None
        entry = _dict(value)
        cached_at = entry.get("cachedAt")
        inquiry_id = entry.get("inquiryId")
        status = entry.get("status")
        if (
            isinstance(cached_at, bool)
            or not isinstance(cached_at, int | float)
            or not isinstance(inquiry_id, str)
            or not isinstance(status, str)
        ):
            return None
        return cls(
            cached_at=float(cached_at),
            inquiry_id=inquiry_id,
            status=cast("InquiryStatus", status),
            verified_at=_date(entry.get("verifiedAt")),
        )


def _options(
    statuses: Sequence[InquiryStatus],
    max_age: int | None,
    onboarding: Onboarding | None,
    cache: Store | None,
    cache_ttl: float,
) -> _LookupOptions:
    accepted = (statuses,) if isinstance(statuses, str) else tuple(statuses)
    if not accepted:
        raise ValueError("Persona needs at least one accepted status.")
    age = cast("object", max_age)
    if age is not None and (isinstance(age, bool) or not isinstance(age, int) or age <= 0):
        raise ValueError("Persona max_age must be a positive integer.")
    ttl = cast("object", cache_ttl)
    if (
        isinstance(ttl, bool)
        or not isinstance(ttl, int | float)
        or not math.isfinite(ttl)
        or ttl < 0
    ):
        raise ValueError("Persona cache_ttl must be a non-negative number of seconds.")
    return _LookupOptions(
        statuses=cast("tuple[InquiryStatus, ...]", accepted),
        max_age=max_age,
        onboarding=onboarding,
        cache=cache,
        cache_ttl=float(ttl),
    )


async def _onboarding_headers(
    onboarding: Onboarding | None, request: Request, reference_id: str | None
) -> HeaderPairs:
    if onboarding is None or isinstance(onboarding, str):
        url = onboarding
    else:
        url = await _resolve(onboarding(request, reference_id))
    if not url:
        return ()
    return (("Link", f'<{url}>; rel="{REL}"'),)


async def _resolve(value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await cast("Awaitable[T]", value)
    return cast("T", value)


def _fresh(verified_at: datetime | None, max_age: int | None, now: float) -> bool:
    if max_age is None:
        return True
    return verified_at is not None and now - verified_at.timestamp() <= max_age


def _date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _iso(value: datetime) -> str:
    """Format as JavaScript's `Date.toISOString` does, for a cache mppx shares."""
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _dict(value: object) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _same_origin(link: object, api_url: str) -> str | None:
    """Return a pagination link as an absolute URL, or None unless it is on the Persona API
    origin, so the API key is never sent to an origin a response names."""
    if not isinstance(link, str):
        return None
    try:
        url = httpx.URL(api_url).join(link)
        if _origin(str(url)) != _origin(api_url):
            return None
    except (httpx.InvalidURL, ValueError):
        return None
    # The absolute URL, not its path: a path such as '//host/x' would resolve to another origin.
    return str(url)


async def verify_wallet(
    *,
    address: str,
    chain_id: int,
    message: str,
    signature: str,
    nonce: str,
    verify: WalletVerifier | None = None,
) -> str:
    """Verify that the signer of ``message`` owns ``address`` and return the wallet's reference
    ID, :func:`~mpp.extensions.identity.persona.did`, to start an inquiry with.

    ``message`` must contain ``nonce``, a single-use value your server issued for this person,
    so a signature cannot be replayed, and the wallet's DID, so the signer commits to the
    chain: the same address can have different owners on different chains.

    Without ``verify``, it accepts EOA (EIP-191 ``personal_sign``) signatures only, which needs
    ``eth-account`` (``pip install "pympp[evm]"``). Pass ``verify`` for smart accounts
    (ERC-1271, ERC-6492); it receives ``chain_id``.

    Raises:
        ValueError: If the message lacks the nonce or the wallet's DID, or the signature does
            not match the address.
        ImportError: Without ``verify`` when ``eth-account`` is not installed.
    """
    if not nonce or nonce not in message:
        raise ValueError("The signed message must contain the nonce.")
    reference_id = did(address, chain_id)
    if reference_id.lower() not in message.lower():
        raise ValueError(f"The signed message must contain the wallet's DID, {reference_id}.")
    check = verify if verify is not None else _eoa_verifier()
    try:
        valid = await _resolve(
            check(address=address, chain_id=chain_id, message=message, signature=signature)
        )
    except Exception:
        valid = False
    if not valid:
        raise ValueError("The signature does not match the address.")
    return reference_id


def _eoa_verifier() -> WalletVerifier:
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
    except ImportError as error:
        raise ImportError(
            f"Cannot verify a wallet signature: {error}. Install the evm extra: "
            'pip install "pympp[evm]", or pass verify'
        ) from error

    def recover(*, address: str, chain_id: int, message: str, signature: str) -> bool:
        signed = bytes.fromhex(signature.removeprefix("0x"))
        recovered = str(
            Account.recover_message(  # pyright: ignore[reportUnknownMemberType]
                encode_defunct(text=message), signature=signed
            )
        )
        return recovered.lower() == address.lower()

    return recover


__all__ = [
    "Onboarding",
    "PaymentReferenceId",
    "Persona",
    "PersonaError",
    "RequestReferenceId",
    "WalletVerifier",
    "create",
    "verify_wallet",
]
