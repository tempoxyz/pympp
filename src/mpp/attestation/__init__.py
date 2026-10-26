"""Request attestation: sign outbound requests and verify signed inbound requests.

Protocol adapters live in :mod:`mpp.attestation.tap` (Trusted Agent Protocol) and
:mod:`mpp.attestation.web_bot_auth` (Web Bot Auth). Both use RFC 9421 HTTP message
signatures and need the ``attestation`` extra: ``pip install pympp[attestation]``.

Example:
    from mpp.attestation import tap
    from mpp.client import Mpp

    signer = tap.signer(intent="payment", key=private_key, key_id="agent-key")
    async with Mpp(methods=[...], attestation={"tap": signer}) as mpp:
        response = await mpp.fetch("https://api.example.com/resource")
"""

from __future__ import annotations

import asyncio
import base64
import secrets
import time
import weakref
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Literal, Protocol, TypeAlias, TypeVar

import httpx

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    from mpp.server.http import Request

T = TypeVar("T")

SignatureAlgorithm: TypeAlias = Literal["ed25519", "rsa-pss-sha512"]
"""RFC 9421 algorithms implemented by the request-attestation signer and verifier."""

ED25519: SignatureAlgorithm = "ed25519"
"""EdDSA using the Ed25519 curve."""
RSA_PSS_SHA512: SignatureAlgorithm = "rsa-pss-sha512"
"""RSASSA-PSS using SHA-512 and a 64-byte salt."""

SIGNATURE_HEADER = "Signature"
"""Carries the RFC 9421 signature bytes."""
SIGNATURE_INPUT_HEADER = "Signature-Input"
"""Carries the RFC 9421 covered components and signature parameters."""


@dataclass(frozen=True, slots=True)
class SigningContext:
    """Values shared by every signer contributing to one HTTP request attempt.

    Reuse one context across protocols so their signatures describe the same attempt.
    A later network retry must use a new context.
    """

    created: int
    """Unix timestamp, in seconds, at which the request attempt was created."""
    nonce: str
    """Base64url-encoded random value identifying this request attempt."""

    @classmethod
    def create(cls) -> SigningContext:
        """Create a context for a new attempt: the current time and a 64-byte random nonce."""
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
        return cls(created=int(time.time()), nonce=nonce)


class Signer(Protocol):
    """Signs each outbound HTTP request, including automatic paid retries."""

    @property
    def protocol(self) -> str:
        """Protocol identifier used for diagnostics."""
        ...

    async def sign(
        self, request: httpx.Request, context: SigningContext | None = None
    ) -> httpx.Request:
        """Return a new request carrying the protocol's signature material."""
        ...


@dataclass(frozen=True, slots=True)
class Absent:
    """The protocol did not appear on the request."""

    status: ClassVar[Literal["absent"]] = "absent"


@dataclass(frozen=True, slots=True)
class Invalid:
    """The protocol appeared but failed validation; the request must be rejected."""

    reason: str
    status: ClassVar[Literal["invalid"]] = "invalid"


@dataclass(frozen=True, slots=True)
class Unverified:
    """Key material or another verification dependency was unavailable."""

    reason: str
    status: ClassVar[Literal["unverified"]] = "unverified"


@dataclass(frozen=True, slots=True)
class Verified(Generic[T]):
    """The protocol verified; ``value`` carries protocol-specific data."""

    value: T
    status: ClassVar[Literal["verified"]] = "verified"


Verification: TypeAlias = "Absent | Invalid | Unverified | Verified[T]"
"""The complete outcome of attempting one protocol verifier."""


class Verifier(Protocol[T]):
    """Verifies one request-attestation protocol carried by an HTTP request."""

    async def verify(self, request: Request) -> Absent | Invalid | Unverified | Verified[T]: ...


@dataclass(frozen=True, slots=True)
class KeyLookup:
    """What a :data:`KeyResolver` receives for one parsed request signature."""

    algorithm: SignatureAlgorithm
    """RFC 9421 algorithm declared by the signature."""
    key_id: str
    """Key identifier declared by the signature."""
    request: Request
    """Request carrying the signature."""
    signature_agent: str | None = None
    """Web Bot Auth only: the HTTPS directory origin from the signed ``Signature-Agent``."""


PublicKey: TypeAlias = "Ed25519PublicKey | RSAPublicKey"
"""An Ed25519 public key, or an RSA one verified with RSASSA-PSS SHA-512."""

KeyResolver: TypeAlias = "Callable[[KeyLookup], Awaitable[PublicKey | None] | PublicKey | None]"
"""Resolves a trusted public key for a parsed signature, synchronously or not."""


@dataclass(frozen=True, slots=True)
class ComposedSigner:
    """Applies several signers in order, sharing one :class:`SigningContext` per call."""

    signers: tuple[Signer, ...]
    protocol: str = "composed"

    async def sign(
        self, request: httpx.Request, context: SigningContext | None = None
    ) -> httpx.Request:
        context = context or SigningContext.create()
        for signer in self.signers:
            request = await signer.sign(request, context)
        return request


def compose_signers(first: Signer, /, *rest: Signer) -> ComposedSigner:
    """Combine signers so every signature on one attempt shares a nonce and timestamp."""
    return ComposedSigner((first, *rest))


async def verify(
    request: Request, verifiers: Mapping[str, Verifier[Any]]
) -> dict[str, Absent | Invalid | Unverified | Verified[Any]]:
    """Run every configured verifier in order and return each outcome by name."""
    return {name: await verifier.verify(request) for name, verifier in verifiers.items()}


class AttestedTransport(httpx.AsyncBaseTransport):
    """An httpx transport that signs every outbound request before sending it.

    Each request gets a new :class:`SigningContext`, so a paid retry carries a fresh nonce.
    """

    def __init__(self, transport: httpx.AsyncBaseTransport, signer: Signer) -> None:
        self._transport = transport
        self._signer = signer

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._transport.handle_async_request(await self._signer.sign(request))

    async def aclose(self) -> None:
        await self._transport.aclose()


def signer_from(signers: Mapping[str, Signer]) -> ComposedSigner:
    """Compose the signers of a client's ``attestation`` option, which must not be empty."""
    values = list(signers.values())
    if not values:
        raise TypeError("Client attestation must configure at least one signer.")
    return compose_signers(*values)


class Guard:
    """Requires every configured verifier to pass before an HTTP payment request is handled.

    The outcome is cached per request object, so handlers evaluating the same request
    verify it (and consume its nonces) once.
    """

    def __init__(self, verifiers: Mapping[str, Verifier[Any]]) -> None:
        if not verifiers:
            raise TypeError("Server attestation must configure at least one verifier.")
        self._verifiers = dict(verifiers)
        self._cache: dict[int, asyncio.Future[tuple[int, str] | None]] = {}

    async def __call__(self, request: Request) -> tuple[int, str] | None:
        """Return the rejection ``(status, message)``, or ``None`` to handle the request."""
        key = id(request)
        if (cached := self._cache.get(key)) is not None:
            return await asyncio.shield(cached)
        task = asyncio.ensure_future(self._check(request))
        self._cache[key] = task
        weakref.finalize(request, self._cache.pop, key, None)
        task.add_done_callback(lambda done: self._forget_failure(key, done))
        return await asyncio.shield(task)

    def _forget_failure(self, key: int, task: asyncio.Future[tuple[int, str] | None]) -> None:
        # A failed task's traceback references the request, so caching it would keep the
        # request alive and its finalizer would never evict the entry.
        if (task.cancelled() or task.exception() is not None) and self._cache.get(key) is task:
            del self._cache[key]

    async def _check(self, request: Request) -> tuple[int, str] | None:
        outcomes = await verify(request, self._verifiers)
        for name, outcome in outcomes.items():
            if isinstance(outcome, Invalid):
                return 401, f'Request attestation "{name}" is invalid: {outcome.reason}'
        for name, outcome in outcomes.items():
            if isinstance(outcome, Verified):
                continue
            if isinstance(outcome, Unverified):
                return 403, f'Request attestation "{name}" could not be verified: {outcome.reason}'
            return 403, f'Request attestation "{name}" is required.'
        return None


__all__ = [
    "ED25519",
    "RSA_PSS_SHA512",
    "SIGNATURE_HEADER",
    "SIGNATURE_INPUT_HEADER",
    "Absent",
    "AttestedTransport",
    "ComposedSigner",
    "Invalid",
    "KeyLookup",
    "KeyResolver",
    "PublicKey",
    "SignatureAlgorithm",
    "Signer",
    "SigningContext",
    "Unverified",
    "Verification",
    "Verified",
    "Verifier",
    "compose_signers",
    "verify",
]
