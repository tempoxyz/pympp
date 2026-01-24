"""HTTP 402 Payment Authentication for Python.

Core types for the Payment HTTP Authentication Scheme.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from mpp._parsing import (
    ParseError,
    format_authorization,
    format_payment_receipt,
    format_www_authenticate,
    parse_authorization,
    parse_payment_receipt,
    parse_www_authenticate,
)
from mpp.errors import (
    BadRequestError,
    InvalidChallengeError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentActionRequiredError,
    PaymentError,
    PaymentExpiredError,
    PaymentInsufficientError,
    PaymentMethodUnsupportedError,
    PaymentRequiredError,
    VerificationFailedError,
)


def _b64url_encode(data: str) -> str:
    """Encode a string to base64url without padding."""
    encoded = base64.urlsafe_b64encode(data.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _b64url_encode_bytes(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    encoded = base64.urlsafe_b64encode(data).decode("ascii")
    return encoded.rstrip("=")


def generate_challenge_id(
    *,
    secret_key: str,
    realm: str,
    method: str,
    intent: str,
    request: dict[str, Any],
    expires: str | None = None,
    digest: str | None = None,
    opaque: dict[str, str] | None = None,
) -> str:
    """Generate HMAC-SHA256 challenge ID per spec.

    The challenge ID is computed as HMAC-SHA256 over the challenge parameters,
    cryptographically binding the ID to its contents. This enables stateless
    verification - the server can verify a challenge was issued by it without
    storing state.

    HMAC input format: realm|method|intent|request_b64|expires|digest|opaque (pipe-delimited).
    All fields are always included; absent optional fields use empty string.
    Output: base64url(HMAC-SHA256(secret_key, input))

    Args:
        secret_key: Server secret for HMAC computation.
        realm: Server realm (e.g., hostname).
        method: Payment method name (e.g., "tempo").
        intent: Intent name (e.g., "charge").
        request: Payment request parameters.
        expires: Optional expiration timestamp (ISO 8601).
        digest: Optional digest of request body.
        opaque: Optional server-defined correlation data.

    Returns:
        Base64url-encoded HMAC-SHA256 of the challenge parameters.

    Example:
        challenge_id = generate_challenge_id(
            secret_key="my-server-secret",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000", "currency": "0x...", "recipient": "0x..."},
        )
    """
    request_json = json.dumps(request, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    request_b64 = _b64url_encode(request_json)

    opaque_b64 = ""
    if opaque is not None:
        opaque_json = json.dumps(opaque, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
        opaque_b64 = _b64url_encode(opaque_json)

    hmac_input = "|".join(
        [
            realm,
            method,
            intent,
            request_b64,
            expires or "",
            digest or "",
            opaque_b64,
        ]
    )

    mac = hmac.new(
        secret_key.encode("utf-8"),
        hmac_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    return _b64url_encode_bytes(mac)


def _constant_time_equal(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class Challenge:
    """A parsed payment challenge from a WWW-Authenticate header.

    Example:
        challenge = Challenge(
            id="challenge-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000000", "currency": "0x...", "recipient": "0x..."},
        )

        # Create with HMAC-bound ID (recommended for servers):
        challenge = Challenge.create(
            secret_key="my-server-secret",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request={"amount": "1000000", ...},
        )
    """

    id: str
    method: str
    intent: str
    request: dict[str, Any]
    realm: str = ""
    request_b64: str = ""
    digest: str | None = None
    expires: str | None = None
    description: str | None = None
    opaque: dict[str, str] | None = None

    @classmethod
    def create(
        cls,
        *,
        secret_key: str,
        realm: str,
        method: str,
        intent: str,
        request: dict[str, Any],
        expires: str | None = None,
        digest: str | None = None,
        description: str | None = None,
        meta: dict[str, str] | None = None,
    ) -> Challenge:
        """Create a Challenge with an HMAC-bound ID.

        The challenge ID is computed as HMAC-SHA256 over the challenge parameters,
        cryptographically binding the ID to its contents. This enables stateless
        verification - the server can verify a challenge was issued by it without
        storing state.

        Args:
            secret_key: Server secret for HMAC computation.
            realm: Server realm (e.g., hostname).
            method: Payment method name (e.g., "tempo").
            intent: Intent name (e.g., "charge").
            request: Payment request parameters.
            expires: Optional expiration timestamp (ISO 8601).
            digest: Optional digest of request body.
            description: Optional human-readable description.
            meta: Optional server-defined correlation data (stored as opaque).

        Returns:
            A Challenge with an HMAC-bound ID.
        """
        challenge_id = generate_challenge_id(
            secret_key=secret_key,
            realm=realm,
            method=method,
            intent=intent,
            request=request,
            expires=expires,
            digest=digest,
            opaque=meta,
        )
        request_json = json.dumps(
            request,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
        )
        request_b64 = _b64url_encode(request_json)
        return cls(
            id=challenge_id,
            method=method,
            intent=intent,
            request=request,
            realm=realm,
            request_b64=request_b64,
            digest=digest,
            expires=expires,
            description=description,
            opaque=meta,
        )

    @classmethod
    def from_www_authenticate(cls, header: str) -> Challenge:
        """Parse a Challenge from a WWW-Authenticate header value."""
        return parse_www_authenticate(header)

    def to_www_authenticate(self, realm: str) -> str:
        """Serialize to a WWW-Authenticate header value."""
        return format_www_authenticate(self, realm)

    def verify(self, secret_key: str, realm: str) -> bool:
        """Verify the challenge ID matches the expected HMAC.

        Recomputes the HMAC from the challenge parameters and compares
        to the stored ID. This allows stateless verification - if the
        IDs match, the server knows it issued this challenge with these
        exact parameters.

        Args:
            secret_key: Server secret used to generate the original ID.
            realm: Server realm used to generate the original ID.

        Returns:
            True if the ID is valid, False otherwise.
        """
        expected_id = generate_challenge_id(
            secret_key=secret_key,
            realm=realm,
            method=self.method,
            intent=self.intent,
            request=self.request,
            expires=self.expires,
            digest=self.digest,
            opaque=self.opaque,
        )
        return _constant_time_equal(self.id, expected_id)

    def to_echo(self) -> ChallengeEcho:
        """Create a ChallengeEcho for use in credentials.

        Returns:
            A ChallengeEcho with the challenge parameters.
        """
        opaque_b64 = None
        if self.opaque is not None:
            opaque_json = json.dumps(
                self.opaque,
                separators=(",", ":"),
                sort_keys=True,
                ensure_ascii=False,
            )
            opaque_b64 = _b64url_encode(opaque_json)
        return ChallengeEcho(
            id=self.id,
            realm=self.realm,
            method=self.method,
            intent=self.intent,
            request=self.request_b64,
            expires=self.expires,
            digest=self.digest,
            opaque=opaque_b64,
        )


@dataclass(frozen=True, slots=True)
class ChallengeEcho:
    """Challenge echo in credential (echoes server challenge parameters).

    This is included in the credential to bind the payment to the original challenge.
    The `request` field is the raw base64url string (not re-encoded).

    Example:
        echo = ChallengeEcho(
            id="challenge-id",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request="eyJhbW91bnQiOiIxMDAwIn0",
        )
    """

    id: str
    realm: str
    method: str
    intent: str
    request: str
    expires: str | None = None
    digest: str | None = None
    opaque: str | None = None


@dataclass(frozen=True, slots=True)
class Credential:
    """The credential passed to the verify function.

    Contains the challenge echo and the payment proof.

    Example:
        echo = ChallengeEcho(
            id="challenge-id",
            realm="api.example.com",
            method="tempo",
            intent="charge",
            request="eyJhbW91bnQiOiIxMDAwIn0",
        )
        credential = Credential(
            challenge=echo,
            payload={"type": "transaction", "signature": "0x..."},
        )
    """

    challenge: ChallengeEcho
    payload: dict[str, Any]
    source: str | None = None

    @classmethod
    def from_authorization(cls, header: str) -> Credential:
        """Parse a Credential from an Authorization header value."""
        return parse_authorization(header)

    def to_authorization(self) -> str:
        """Serialize to an Authorization header value."""
        return format_authorization(self)


@dataclass(frozen=True, slots=True)
class Receipt:
    """Payment receipt returned after verification.

    Example:
        from datetime import datetime, UTC

        receipt = Receipt(
            status="success",
            timestamp=datetime.now(UTC),
            reference="0x...",
        )
    """

    status: Literal["success"]
    timestamp: datetime
    reference: str
    method: str = ""
    external_id: str | None = None
    extra: dict[str, Any] | None = None

    @classmethod
    def from_payment_receipt(cls, header: str) -> Receipt:
        """Parse a Receipt from a Payment-Receipt header value."""
        return parse_payment_receipt(header)

    def to_payment_receipt(self) -> str:
        """Serialize to a Payment-Receipt header value."""
        return format_payment_receipt(self)

    @classmethod
    def success(
        cls,
        reference: str,
        timestamp: datetime | None = None,
        method: str = "tempo",
        external_id: str | None = None,
    ) -> Receipt:
        """Create a success receipt with current timestamp."""
        return cls(
            status="success",
            timestamp=timestamp or datetime.now(UTC),
            reference=reference,
            method=method,
            external_id=external_id,
        )


from . import _body_digest as BodyDigest  # noqa: E402
from . import _expires as Expires  # noqa: E402
