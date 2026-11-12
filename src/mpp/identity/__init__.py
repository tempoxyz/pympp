"""Identity for paid routes: verifiers, payment checks and provers (mppx `Identity`).

A server route can require an identity before it issues a `402`, and check the payer's
identity on the paid retry before settling. A client attaches identity proofs to its requests.

Server side:

- :class:`Verifier` checks one identity protocol on every request, before any Challenge.
- :class:`PaymentCheck` checks the payer on the paid retry, after the Credential is
  authenticated and before it settles; every `402` of its route lists its
  :attr:`PaymentCheck.requires` in the ``Identity-Required`` header.
- :class:`Route` holds a route's verifiers and payment check: pass it, or a list of
  verifiers, as a route's ``identity`` option, such as
  ``mpp.charge(amount="1", identity=[verifier])``.
- :func:`any_of` accepts the first of several verifiers; :func:`from_fn` builds one from a
  function.

Outcomes are :class:`Valid` or :class:`Rejected`, whose fixed status decides the HTTP status
(:data:`STATUS_CODES`) and, when several reject, which one wins (:data:`PRECEDENCE`).

Client side, a :class:`Prover` adds one protocol's proof to every request to its ``scope``;
pass provers to ``mpp.client.Mpp(identity=[...])``.

Every type here is immutable. Verifiers and payment checks compare by identity, so the same
object looks up its verified value in :class:`Results`.
"""

from __future__ import annotations

import base64
import os
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeAlias, TypeVar, cast

import httpx

from mpp import Challenge, Credential
from mpp.identity import _requirements

if TYPE_CHECKING:
    from mpp.server.http import Request

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)

RejectionStatus: TypeAlias = Literal["missing", "invalid", "forbidden", "unavailable"]
"""The fixed status of a rejected identity.

- ``missing``: no proof was presented (401).
- ``invalid``: a proof was presented but did not verify (401).
- ``forbidden``: the proof verified, but the identity is not allowed (403).
- ``unavailable``: the proof could not be checked right now, such as an issuer outage (503).
"""

STATUS_CODES: Mapping[RejectionStatus, int] = MappingProxyType(
    {"missing": 401, "invalid": 401, "forbidden": 403, "unavailable": 503}
)
"""The HTTP status code of each rejected status."""

PRECEDENCE: tuple[RejectionStatus, ...] = ("forbidden", "unavailable", "invalid", "missing")
"""Rejected statuses from highest to lowest precedence: when several reject, the first wins."""

_DEFAULT_REASONS: Mapping[RejectionStatus, str] = MappingProxyType(
    {
        "missing": "Identity verification is required.",
        "invalid": "The identity proof is invalid.",
        "forbidden": "This identity is not allowed.",
        "unavailable": "Identity verification is unavailable.",
    }
)

IDENTITY_REQUIRED_HEADER = _requirements.HEADER
"""The `402` response header listing the identities a payment check requires."""

REQUEST_HEADERS: tuple[str, ...] = ("identity-attestation", "identity-presentation")
"""Bearer identity request headers, lowercased. The client never sends them across origins."""

HeaderPairs: TypeAlias = tuple[tuple[str, str], ...]
HeadersInput: TypeAlias = Mapping[str, str] | Iterable[tuple[str, str]] | None


def _header_pairs(headers: HeadersInput) -> HeaderPairs:
    if headers is None:
        return ()
    if isinstance(headers, Mapping):
        mapping = cast("Mapping[str, str]", headers)
        return tuple((str(name), str(value)) for name, value in mapping.items())
    return tuple((str(name), str(value)) for name, value in headers)


# --- Outcomes -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Valid(Generic[T_co]):
    """A verified identity, carrying its value."""

    value: T_co
    status: Literal["valid"] = field(default="valid", init=False)


@dataclass(frozen=True, slots=True)
class Rejected:
    """A rejected identity: its fixed status, a reason, and headers for the client.

    ``headers`` (such as a ``WWW-Authenticate`` challenge) are sent with the rejection. An empty
    ``reason`` is replaced with the status's default. An unknown status fails closed to
    ``invalid``.
    """

    status: RejectionStatus
    reason: str = ""
    headers: HeaderPairs = ()

    def __post_init__(self) -> None:
        status: str = self.status
        if status not in STATUS_CODES:
            object.__setattr__(self, "status", "invalid")
            object.__setattr__(self, "reason", "The identity verifier returned an unknown status.")
        elif not self.reason:
            object.__setattr__(self, "reason", _DEFAULT_REASONS[self.status])
        object.__setattr__(self, "headers", _header_pairs(self.headers))

    @property
    def code(self) -> int:
        """The HTTP status code the rejection is sent with."""
        return STATUS_CODES[self.status]


Verification: TypeAlias = Valid[T] | Rejected
"""The outcome of a verifier or payment check."""


def missing(reason: str = "", headers: HeadersInput = None) -> Rejected:
    """No proof was presented (401)."""
    return Rejected("missing", reason, _header_pairs(headers))


def invalid(reason: str = "", headers: HeadersInput = None) -> Rejected:
    """A proof was presented but did not verify (401)."""
    return Rejected("invalid", reason, _header_pairs(headers))


def forbidden(reason: str = "", headers: HeadersInput = None) -> Rejected:
    """The proof verified, but the identity is not allowed (403)."""
    return Rejected("forbidden", reason, _header_pairs(headers))


def unavailable(reason: str = "", headers: HeadersInput = None) -> Rejected:
    """The proof could not be checked right now (503)."""
    return Rejected("unavailable", reason, _header_pairs(headers))


def _decide(rejections: Sequence[Rejected]) -> Rejected:
    """Combine rejections into one: the highest-precedence status decides status and reason
    (the first on ties), with every rejection's headers.

    Raises:
        ValueError: If ``rejections`` is empty.
    """
    if not rejections:
        raise ValueError("an identity decision needs at least one rejection")
    winner = min(rejections, key=lambda rejected: PRECEDENCE.index(rejected.status))
    headers = tuple(pair for rejected in rejections for pair in rejected.headers)
    return Rejected(winner.status, winner.reason, headers)


# --- Server ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Requirement:
    """One identity a payment check requires, listed in the 402's ``Identity-Required``.

    ``type`` is a structured-field token such as ``tempo-id``; ``issuer``, when set, names who
    must issue it.
    """

    type: str
    issuer: str | None = None


@dataclass(frozen=True, slots=True)
class PaymentCheckInput:
    """What a payment check sees: the request, the Challenge it answers, and its Credential.

    ``credential`` is the paid retry's, with its payload parsed.
    """

    request: Request
    challenge: Challenge
    credential: Credential


@dataclass(frozen=True, slots=True, eq=False)
class Verifier(Generic[T]):
    """Verifies one identity protocol on every request of a route, before any Challenge.

    ``authorization`` says the verifier reads ``Authorization``: its route needs a server created
    with ``requires_auth=True``, so Payment Credentials travel in ``Payment-Authorization``.
    """

    verify: Callable[[Request], Awaitable[Verification[T]]]
    authorization: bool = False


@dataclass(frozen=True, slots=True)
class AnyOfValue:
    """The value of an :func:`any_of` verifier: the first valid member's index and value."""

    index: int
    value: Any


@dataclass(frozen=True, slots=True, eq=False)
class AnyOf(Verifier[AnyOfValue]):
    """A verifier valid when any of its ``members`` is; see :func:`any_of`."""

    members: tuple[Verifier[Any], ...] = ()


def any_of(*verifiers: Verifier[Any]) -> AnyOf:
    """Accept the first of several identity protocols that verifies.

    Every member runs, so each presented proof's replay nonce is spent. Valid if any member is
    (the first valid one wins, and :meth:`Results.get` finds its value by the member too);
    otherwise the highest-precedence rejection decides, with every member's headers, and a
    ``missing`` outcome says none of the accepted proofs was presented.

    Raises:
        ValueError: With fewer than two verifiers.
    """
    if len(verifiers) < 2:
        raise ValueError("any_of() needs at least two verifiers")
    if any(not isinstance(verifier, Verifier) for verifier in verifiers):
        raise TypeError("any_of() accepts only verifiers")
    members = tuple(verifiers)

    async def verify(request: Request) -> Verification[AnyOfValue]:
        return _combine_any_of([await member.verify(request) for member in members])

    return AnyOf(
        verify=verify,
        authorization=any(member.authorization for member in members),
        members=members,
    )


def _combine_any_of(outcomes: Sequence[Verification[Any]]) -> Verification[AnyOfValue]:
    """Combine the outcomes of :func:`any_of` members, in member order."""
    for index, outcome in enumerate(outcomes):
        if isinstance(outcome, Valid):
            return Valid(AnyOfValue(index, outcome.value))
    decision = _decide(cast("Sequence[Rejected]", outcomes))
    if decision.status == "missing":
        return Rejected(
            "missing", "None of the accepted identity proofs was presented.", decision.headers
        )
    return decision


@dataclass(frozen=True, slots=True, eq=False)
class PaymentCheck(Generic[T]):
    """Checks the payer's identity on the paid retry, before the Credential settles.

    Every 402 of its route lists ``requires`` in ``Identity-Required``. ``verify`` runs once on
    the paid retry, after the Credential's HMAC, pinned fields, expiry and payload are checked;
    anything but :class:`Valid` rejects with its fixed status and no fresh 402, since the client
    may already have pushed the payment. A route with a payment check does not accept x402
    payments, which name no Challenge a proof could bind to.

    - ``authorization``: the check reads ``Authorization``, so its route needs a server created
      with ``requires_auth=True``.
    - ``payer``: returns the account the check vetted from its value. After settlement the
      engine compares it with the account the payment method reports (``Receipt.payer``) and
      rejects the request as ``forbidden`` when they differ, or when the method reports none,
      so a check cannot be satisfied with one account and paid from another. The payment has
      settled by then: a check that names a payer should refuse, in ``verify``, intents whose
      receipts name no payer.

    Raises:
        ValueError: If a requirement cannot be serialized.
    """

    requires: tuple[Requirement, ...]
    verify: Callable[[PaymentCheckInput], Awaitable[Verification[T]]]
    authorization: bool = False
    payer: Callable[[T], str | None] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "requires", tuple(self.requires))
        _requirements.serialize(self.requires)


@dataclass(frozen=True, slots=True)
class Route:
    """A route's identity: verifiers that must all be valid, and an optional payment check."""

    request: tuple[Verifier[Any], ...] = ()
    payment: PaymentCheck[Any] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.request, Verifier):
            raise TypeError("Route request must be a sequence of verifiers; wrap one in a list")
        object.__setattr__(self, "request", tuple(self.request))
        if any(not isinstance(verifier, Verifier) for verifier in self.request):
            raise TypeError("Route request must contain only verifiers")
        if self.payment is not None and not isinstance(self.payment, PaymentCheck):
            raise TypeError("Route payment must be a PaymentCheck")

    @property
    def empty(self) -> bool:
        """Whether the route checks no identity."""
        return not self.request and self.payment is None

    @property
    def requirements(self) -> tuple[Requirement, ...]:
        """The identities every 402 of the route lists."""
        return self.payment.requires if self.payment is not None else ()

    @property
    def authorization(self) -> bool:
        """Whether a verifier or the payment check reads ``Authorization``."""
        payment = self.payment is not None and self.payment.authorization
        return payment or any(verifier.authorization for verifier in self.request)

    @classmethod
    def of(cls, value: Route | Sequence[Verifier[Any]] | None) -> Route:
        """Read a route's ``identity`` option: a :class:`Route`, a list of verifiers, or None.

        Raises:
            TypeError: For anything else, such as a bare verifier, so a route never silently
                runs without its checks.
        """
        if value is None:
            return _EMPTY_ROUTE
        if isinstance(value, Route):
            return value
        if isinstance(value, Verifier | PaymentCheck) or not isinstance(value, Sequence):
            raise TypeError(
                "identity must be a list of verifiers or an identity.Route; "
                "wrap a single verifier in a list"
            )
        return cls(request=tuple(value))


_EMPTY_ROUTE = Route()


@dataclass(frozen=True, slots=True)
class Rejection:
    """Why a route rejected a request's identity (``PaymentRequired.rejection``).

    ``stage`` is ``request`` for a verifier and ``payment`` for the payment check.
    """

    stage: Literal["request", "payment"]
    status: RejectionStatus
    reason: str


@dataclass(frozen=True, slots=True)
class Results:
    """Verified identity values, looked up by the verifier or payment check that produced them."""

    values: Mapping[Verifier[Any] | PaymentCheck[Any], Any] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))

    def get(self, source: Verifier[T] | PaymentCheck[T]) -> T | None:
        """Return the verified value of ``source``, or None if it did not run or match."""
        return cast("T | None", self.values.get(source))

    def __contains__(self, source: object) -> bool:
        return source in self.values


_EMPTY_RESULTS = Results()


class RejectionError(Exception):
    """Raised from a :func:`from_fn` function to reject the identity a request carries."""

    status: Literal["invalid", "forbidden", "unavailable"]

    def __init__(
        self, reason: str, *, status: Literal["invalid", "forbidden", "unavailable"] = "invalid"
    ) -> None:
        if status not in ("invalid", "forbidden", "unavailable"):
            raise ValueError("RejectionError status must be invalid, forbidden or unavailable")
        super().__init__(reason)
        self.status = status


def from_fn(
    verify: Callable[[Request], Awaitable[T | None]],
    *,
    challenge: HeadersInput = None,
    authorization: bool = False,
) -> Verifier[T]:
    """Build a verifier from a function, such as a lookup in your own database (mppx `from`).

    The function returns the caller's identity, None when the request carries none
    (``missing``, with the ``challenge`` headers), or raises :class:`RejectionError` to reject
    the identity it carries. Read the value in the route with
    ``result.identity.get(verifier)``.

    Example::

        async def lookup(request):
            key = request.headers.get("X-Api-Key")
            if key is None:
                return None
            customer = await db.customer_by_key(key)
            if customer is None:
                raise identity.RejectionError("Unknown API key.", status="forbidden")
            return customer

        customer = identity.from_fn(lookup)
        mpp.charge(amount="1", identity=[customer])
    """
    headers = _header_pairs(challenge)

    async def run(request: Request) -> Verification[T]:
        try:
            value = await verify(request)
        except RejectionError as error:
            return Rejected(error.status, str(error), headers)
        if value is None:
            return Rejected("missing", "", headers)
        return Valid(value)

    return Verifier(verify=run, authorization=authorization)


# --- Client ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProveContext:
    """Values shared by every prover on one HTTP attempt; each attempt gets a new one.

    ``created`` (Unix seconds) and ``nonce`` (64 random bytes, base64url) are RFC 9421's.
    ``challenge`` is set on a paid attempt, so a proof can bind to its ``id``.
    """

    created: int
    nonce: str
    challenge: Challenge | None = None

    @classmethod
    def new(cls, challenge: Challenge | None = None) -> ProveContext:
        nonce = base64.urlsafe_b64encode(os.urandom(64)).rstrip(b"=").decode("ascii")
        return cls(created=int(time.time()), nonce=nonce, challenge=challenge)


@dataclass(frozen=True, slots=True)
class PrepareContext:
    """Passed to :attr:`Prover.prepare` for a 402 before the payment retry."""

    challenge: Challenge
    requirements: tuple[Requirement, ...]


@dataclass(frozen=True, slots=True)
class RetryContext:
    """Passed to :attr:`Prover.retry` with a rejected response: the request, as proved and sent."""

    request: httpx.Request


ProverScope: TypeAlias = tuple[str, ...] | Literal["*"]
"""Exact origins a prover runs for, or ``"*"`` for any."""


@dataclass(frozen=True, slots=True, eq=False)
class Prover:
    """Adds one identity protocol's proof to outbound requests.

    - ``scope``: the exact origins it runs for, such as ``("https://api.example",)``, or ``"*"``.
    - ``prove``: returns a copy of the request carrying the proof (see :func:`with_headers`).
    - ``headers``: sensitive headers it writes, never sent across origins on a redirect.
    - ``prepare``: prepares a proof from a 402 before the paid retry.
    - ``retry``: given a rejected (non-402) response to an unpaid request, returns headers to
      resend it once with, or None. Payment credential headers it returns are ignored.
    """

    scope: ProverScope
    prove: Callable[[httpx.Request, ProveContext], Awaitable[httpx.Request]]
    headers: tuple[str, ...] = ()
    prepare: Callable[[httpx.Response, PrepareContext], Awaitable[None]] | None = None
    retry: Callable[[httpx.Response, RetryContext], Awaitable[Mapping[str, str] | None]] | None = (
        None
    )

    def __post_init__(self) -> None:
        scope: object = self.scope
        if scope != "*":
            if isinstance(scope, str) or not isinstance(scope, Iterable):
                raise TypeError('Prover scope must be "*" or a sequence of origins')
            origins = tuple(cast("Iterable[object]", scope))
            if any(not isinstance(origin, str) for origin in origins):
                raise TypeError("Prover scope origins must be strings")
            object.__setattr__(self, "scope", tuple(_origin(str(o)) for o in origins))
        object.__setattr__(self, "headers", tuple(name.lower() for name in self.headers))

    def covers(self, url: httpx.URL | str) -> bool:
        """Whether the prover runs for a request to ``url``."""
        return self.scope == "*" or _origin(str(url)) in self.scope


def _origin(url: str) -> str:
    parsed = httpx.URL(url)
    default = {"http": 80, "https": 443}.get(parsed.scheme)
    port = "" if parsed.port in (None, default) else f":{parsed.port}"
    return f"{parsed.scheme}://{parsed.host}{port}"


def with_headers(request: httpx.Request, headers: Mapping[str, str]) -> httpx.Request:
    """Return a copy of ``request`` with ``headers`` set, for a prover's ``prove``."""
    merged = httpx.Headers(request.headers)
    for name, value in headers.items():
        merged[name] = value
    return httpx.Request(
        request.method,
        request.url,
        headers=merged,
        stream=request.stream,
        extensions=dict(request.extensions),
    )


__all__ = [
    "_DEFAULT_REASONS",
    "IDENTITY_REQUIRED_HEADER",
    "PRECEDENCE",
    "REQUEST_HEADERS",
    "STATUS_CODES",
    "AnyOf",
    "AnyOfValue",
    "PaymentCheck",
    "PaymentCheckInput",
    "PrepareContext",
    "ProverScope",
    "ProveContext",
    "Prover",
    "Rejected",
    "Rejection",
    "RejectionError",
    "RejectionStatus",
    "Requirement",
    "Results",
    "RetryContext",
    "Route",
    "Valid",
    "Verification",
    "Verifier",
    "any_of",
    "forbidden",
    "from_fn",
    "invalid",
    "missing",
    "unavailable",
    "with_headers",
]
