"""Trusted Agent Protocol (TAP) agent-recognition signatures.

TAP verifies trusted agent participation and request integrity. It does not, on its own,
recognize the consumer or authorize a payment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import httpx

from mpp.attestation import (
    Absent,
    Invalid,
    KeyResolver,
    SigningContext,
    Unverified,
    Verified,
)
from mpp.attestation import _signature as signature
from mpp.attestation._signature import PrivateKey
from mpp.store import ExpiringStore

if TYPE_CHECKING:
    from mpp.server.http import Request

PROTOCOL = "tap"
"""Identifier of TAP signers and of TAP nonces in replay storage."""
LABEL = "tap"
"""RFC 9421 signature label used when no label is configured."""
MAXIMUM_SIGNATURE_LIFETIME = 8 * 60
"""Maximum lifetime, in seconds, TAP permits for an agent signature."""
BROWSE_TAG = "agent-browser-auth"
"""Tag of an agent browsing or discovering a merchant."""
PAYMENT_TAG = "agent-payer-auth"
"""Tag of an agent executing a payment-related interaction."""
REQUIRED_COMPONENTS = (signature.AUTHORITY, signature.PATH)
"""HTTP components every TAP agent signature must cover."""

Intent = Literal["browse", "payment"]


@dataclass(frozen=True, slots=True)
class VerifiedRequest:
    """A verified TAP agent-recognition signature."""

    key_id: str
    """Key identity recognized by the merchant's TAP trust store."""
    nonce: str
    """Session nonce bound to the signature."""
    intent: Intent
    """Interaction type established by the signature tag."""


@dataclass(frozen=True, slots=True)
class TapSigner:
    """Signs requests with TAP's ``agent-browser-auth`` or ``agent-payer-auth`` tag."""

    key: PrivateKey
    key_id: str
    tag: str
    expires_in: int
    label: str
    protocol: str = PROTOCOL

    async def sign(
        self, request: httpx.Request, context: SigningContext | None = None
    ) -> httpx.Request:
        return await signature.sign(
            request,
            components=REQUIRED_COMPONENTS,
            context=context,
            expires_in=self.expires_in,
            key=self.key,
            key_id=self.key_id,
            label=self.label,
            tag=self.tag,
        )


@dataclass(frozen=True, slots=True)
class TapVerifier:
    """Verifies TAP agent-recognition signatures and consumes their nonces."""

    key_resolver: KeyResolver
    nonce_store: ExpiringStore

    def __post_init__(self) -> None:
        signature.require_expiring_store(self.nonce_store)

    async def verify(
        self, request: Request
    ) -> Absent | Invalid | Unverified | Verified[VerifiedRequest]:
        result = await signature.verify(
            request,
            key_resolver=self.key_resolver,
            max_age=MAXIMUM_SIGNATURE_LIFETIME,
            nonce_namespace=PROTOCOL,
            nonce_store=self.nonce_store,
            required_components=REQUIRED_COMPONENTS,
            tag=(BROWSE_TAG, PAYMENT_TAG),
        )
        if not isinstance(result, Verified):
            return result
        return Verified(
            VerifiedRequest(
                key_id=result.value.key_id,
                nonce=result.value.nonce,
                intent="payment" if result.value.tag == PAYMENT_TAG else "browse",
            )
        )


def signer(
    *,
    intent: Intent,
    key: PrivateKey,
    key_id: str,
    expires_in: int = MAXIMUM_SIGNATURE_LIFETIME,
    label: str = LABEL,
) -> TapSigner:
    """Create a TAP request signer.

    Args:
        intent: TAP signature type for the request.
        key: Ed25519 or RSA private key provisioned to the agent provider.
        key_id: Identifier the merchant uses to resolve the signing public key.
        expires_in: Signature lifetime in seconds, at most eight minutes.
        label: RFC 9421 dictionary label.
    """
    if (
        isinstance(expires_in, bool)
        or not isinstance(expires_in, int)
        or not 0 < expires_in <= MAXIMUM_SIGNATURE_LIFETIME
    ):
        raise ValueError(
            f"TAP expires_in must be an integer from 1 to {MAXIMUM_SIGNATURE_LIFETIME}."
        )
    tag = PAYMENT_TAG if intent == "payment" else BROWSE_TAG
    return TapSigner(key=key, key_id=key_id, tag=tag, expires_in=expires_in, label=label)


def verifier(*, key_resolver: KeyResolver, nonce_store: ExpiringStore) -> TapVerifier:
    """Create a TAP signature verifier.

    Args:
        key_resolver: Resolves a TAP-approved public key by its ``keyid`` and algorithm.
        nonce_store: Consumes each nonce atomically until its signature expires; share it
            across instances.
    """
    return TapVerifier(key_resolver=key_resolver, nonce_store=nonce_store)
