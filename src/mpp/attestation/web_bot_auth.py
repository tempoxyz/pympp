"""Web Bot Auth signatures, HTTPS-directory profile.

The signed ``Signature-Agent`` header links a request to the HTTPS origin of an HTTP Message
Signatures Directory. Direct key configuration and other discovery types are out of scope.
Verification establishes the identity of an automated client only: never use it on its own
as user or payment authorization.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import http_sf
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mpp.attestation import (
    Absent,
    Invalid,
    KeyLookup,
    KeyResolver,
    SigningContext,
    Unverified,
    Verified,
)
from mpp.attestation import _signature as signature
from mpp.attestation._signature import PrivateKey, SignatureInput
from mpp.store import ExpiringStore

if TYPE_CHECKING:
    from mpp.server.http import Request

PROTOCOL = "web-bot-auth"
"""Identifier of Web Bot Auth signers and of their nonces in replay storage."""
DISCOVERY_TYPE = "directory"
"""The ``Signature-Agent`` discovery type this adapter supports."""
LABEL = "webbot"
"""RFC 9421 signature label used when no label is configured."""
TAG = "web-bot-auth"
"""Tag identifying a Web Bot Auth request signature."""
SIGNATURE_AGENT_HEADER = "Signature-Agent"
"""Structured header linking a signature to its HTTPS directory origin."""
DEFAULT_SIGNATURE_LIFETIME = 60
"""Default lifetime, in seconds, of a bot request signature."""
DEFAULT_MAXIMUM_SIGNATURE_LIFETIME = 24 * 60 * 60
"""Default verifier limit, the draft's recommended 24-hour maximum."""
REQUIRED_COMPONENTS = (signature.AUTHORITY, signature.SIGNATURE_AGENT)
"""HTTP components this directory profile requires."""

_THUMBPRINT = re.compile(r"[A-Za-z0-9_-]{43}")


@dataclass(frozen=True, slots=True)
class VerifiedRequest:
    """A verified Web Bot Auth request signature."""

    key_id: str
    """RFC 7638 thumbprint of the bot's public key."""
    signature_agent: str
    """HTTPS directory origin carried in the signed ``Signature-Agent`` header."""
    nonce: str
    """Signature nonce supplied by the bot."""


def jwk_thumbprint(key: Ed25519PublicKey | RSAPublicKey) -> str:
    """Return the RFC 7638 SHA-256 JWK thumbprint of an Ed25519 or RSA public key."""
    if isinstance(key, Ed25519PublicKey):
        x = _b64url(key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        jwk: dict[str, str] = {"crv": "Ed25519", "kty": "OKP", "x": x}
    elif isinstance(key, RSAPublicKey):
        numbers = key.public_numbers()
        jwk = {
            "e": _b64url(_int_bytes(numbers.e)),
            "kty": "RSA",
            "n": _b64url(_int_bytes(numbers.n)),
        }
    else:
        raise TypeError("Web Bot Auth requires an Ed25519 or RSA public key.")
    canonical = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    return _b64url(hashlib.sha256(canonical).digest())


@dataclass(frozen=True, slots=True)
class WebBotAuthSigner:
    """Signs requests with a ``Signature-Agent`` directory member and ``@authority``."""

    key: PrivateKey
    key_id: str
    signature_agent: str
    signature_agent_key: str
    expires_in: int
    label: str
    protocol: str = PROTOCOL

    async def sign(
        self, request: httpx.Request, context: SigningContext | None = None
    ) -> httpx.Request:
        agents = signature.parse_dictionary_header(request.headers, SIGNATURE_AGENT_HEADER)
        if self.signature_agent_key in agents:
            raise ValueError(f'Signature-Agent member "{self.signature_agent_key}" already exists.')
        agents[self.signature_agent_key] = (self.signature_agent, {})
        headers = httpx.Headers(request.headers)
        headers[SIGNATURE_AGENT_HEADER] = http_sf.ser(agents)
        return await signature.sign(
            signature.with_headers(request, headers),
            components=(
                signature.AUTHORITY,
                signature.Component(signature.SIGNATURE_AGENT, {"key": self.signature_agent_key}),
            ),
            context=context,
            expires_in=self.expires_in,
            key=self.key,
            key_id=self.key_id,
            label=self.label,
            tag=TAG,
        )


@dataclass(frozen=True, slots=True)
class WebBotAuthVerifier:
    """Verifies Web Bot Auth directory-profile signatures and consumes their nonces."""

    key_resolver: KeyResolver
    nonce_store: ExpiringStore
    max_age: int

    def __post_init__(self) -> None:
        signature.require_expiring_store(self.nonce_store)

    async def verify(
        self, request: Request
    ) -> Absent | Invalid | Unverified | Verified[VerifiedRequest]:
        origin: list[str] = []

        def validate(signature_input: SignatureInput, request: Request) -> str | None:
            reason = _validate(signature_input, request)
            if isinstance(reason, tuple):
                origin.append(reason[0])
                return None
            return reason

        def resolve(lookup: KeyLookup) -> Any:
            return self.key_resolver(dataclasses.replace(lookup, signature_agent=origin[0]))

        result = await signature.verify(
            request,
            key_resolver=resolve,
            max_age=self.max_age,
            nonce_namespace=PROTOCOL,
            nonce_store=self.nonce_store,
            required_components=REQUIRED_COMPONENTS,
            tag=(TAG,),
            validate=validate,
            validate_key=_validate_key,
        )
        if not isinstance(result, Verified):
            return result
        return Verified(
            VerifiedRequest(
                key_id=result.value.key_id, signature_agent=origin[0], nonce=result.value.nonce
            )
        )


def signer(
    *,
    key: PrivateKey,
    key_id: str,
    signature_agent: str,
    signature_agent_key: str | None = None,
    expires_in: int = DEFAULT_SIGNATURE_LIFETIME,
    label: str = LABEL,
) -> WebBotAuthSigner:
    """Create a Web Bot Auth request signer.

    Args:
        key: Ed25519 or RSA private key registered for the bot.
        key_id: RFC 7638 JWK thumbprint of the registered public key (:func:`jwk_thumbprint`).
        signature_agent: HTTPS directory origin, sent with the default ``directory`` type.
        signature_agent_key: ``Signature-Agent`` member name; defaults to ``label``.
        expires_in: Signature lifetime in seconds.
        label: RFC 9421 dictionary label.
    """
    origin = _directory_origin(signature_agent)
    if not _THUMBPRINT.fullmatch(key_id):
        raise ValueError("Web Bot Auth key_id must be an RFC 7638 SHA-256 JWK thumbprint.")
    if origin is None:
        raise ValueError("Signature-Agent must identify a valid HTTPS origin.")
    if isinstance(expires_in, bool) or not isinstance(expires_in, int) or expires_in <= 0:
        raise ValueError("Web Bot Auth expires_in must be a positive integer.")
    return WebBotAuthSigner(
        key=key,
        key_id=key_id,
        signature_agent=origin,
        signature_agent_key=signature_agent_key or label,
        expires_in=expires_in,
        label=label,
    )


def verifier(
    *,
    key_resolver: KeyResolver,
    nonce_store: ExpiringStore,
    max_age: int = DEFAULT_MAXIMUM_SIGNATURE_LIFETIME,
) -> WebBotAuthVerifier:
    """Create a Web Bot Auth directory-profile verifier.

    Args:
        key_resolver: Resolves a public key for the advertised directory, given as
            ``KeyLookup.signature_agent``. Apply your trust policy before any network
            lookup; never fetch an arbitrary caller-provided origin.
        nonce_store: Consumes each nonce atomically until its signature expires; share it
            across instances.
        max_age: Maximum accepted signature lifetime in seconds.
    """
    if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age <= 0:
        raise ValueError("Web Bot Auth max_age must be a positive integer.")
    return WebBotAuthVerifier(key_resolver=key_resolver, nonce_store=nonce_store, max_age=max_age)


def _validate(signature_input: SignatureInput, request: Request) -> str | tuple[str]:
    if not _THUMBPRINT.fullmatch(signature_input.key_id):
        return "The Web Bot Auth keyid must be an RFC 7638 SHA-256 JWK thumbprint."
    component = next(
        (c for c in signature_input.components if c.id == signature.SIGNATURE_AGENT), None
    )
    key = component.parameters.get("key") if component else None
    if type(key) is not str:
        return "The signed Signature-Agent component must identify a dictionary member."
    if not request.headers.get(SIGNATURE_AGENT_HEADER):
        return "The Signature-Agent header is required."
    try:
        agents = signature.parse_dictionary_header(request.headers, SIGNATURE_AGENT_HEADER)
    except ValueError:
        return "The Signature-Agent header must be a structured dictionary."
    agent = agents.get(key)
    if agent is None or type(agent[0]) is not str:
        return "The signed Signature-Agent member must be an HTTPS URL."
    discovery = agent[1].get("type")
    if discovery is not None and (
        not isinstance(discovery, http_sf.Token) or str(discovery) != DISCOVERY_TYPE
    ):
        return "The Signature-Agent discovery type is not supported by this directory profile."
    origin = _directory_origin(agent[0])
    if origin is None:
        return "The Signature-Agent header must identify a valid HTTPS origin."
    return (origin,)


def _validate_key(key: Any, signature_input: SignatureInput, request: Request) -> str | None:
    try:
        thumbprint = jwk_thumbprint(key)
    except Exception:
        return "The Web Bot Auth key must be an Ed25519 or RSA public key."
    if thumbprint != signature_input.key_id:
        return "The Web Bot Auth key does not match its RFC 7638 keyid."
    return None


def _directory_origin(value: str) -> str | None:
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, TypeError):
        return None
    if (
        url.scheme != "https"
        or not url.raw_host
        or url.userinfo
        or url.raw_path != b"/"
        or url.fragment
    ):
        return None
    return f"https://{url.netloc.decode('ascii')}"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _int_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
