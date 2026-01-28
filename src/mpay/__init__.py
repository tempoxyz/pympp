"""HTTP 402 Payment Authentication for Python.

Core types for the Payment HTTP Authentication Scheme.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from mpay._parsing import (
    ParseError,
    format_authorization,
    format_payment_receipt,
    format_www_authenticate,
    parse_authorization,
    parse_payment_receipt,
    parse_www_authenticate,
)

__all__ = ["Challenge", "Credential", "ParseError", "Receipt"]


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
    """

    id: str
    method: str
    intent: str
    request: dict[str, Any]
    digest: str | None = None
    expires: str | None = None
    description: str | None = None

    @classmethod
    def from_www_authenticate(cls, header: str) -> "Challenge":
        """Parse a Challenge from a WWW-Authenticate header value."""
        return parse_www_authenticate(header)

    def to_www_authenticate(self, realm: str) -> str:
        """Serialize to a WWW-Authenticate header value."""
        return format_www_authenticate(self, realm)


@dataclass(frozen=True, slots=True)
class Credential:
    """The credential passed to the verify function.

    Example:
        credential = Credential(
            id="challenge-id",
            payload={"signature": "0x..."},
        )
    """

    id: str
    payload: dict[str, Any]
    source: str | None = None

    @classmethod
    def from_authorization(cls, header: str) -> "Credential":
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

    status: Literal["success", "failed"]
    timestamp: datetime
    reference: str

    @classmethod
    def from_payment_receipt(cls, header: str) -> "Receipt":
        """Parse a Receipt from a Payment-Receipt header value."""
        return parse_payment_receipt(header)

    def to_payment_receipt(self) -> str:
        """Serialize to a Payment-Receipt header value."""
        return format_payment_receipt(self)

    @classmethod
    def success(cls, reference: str, timestamp: datetime | None = None) -> "Receipt":
        """Create a success receipt with current timestamp."""
        return cls(
            status="success",
            timestamp=timestamp or datetime.now(UTC),
            reference=reference,
        )

    @classmethod
    def failed(cls, reference: str, timestamp: datetime | None = None) -> "Receipt":
        """Create a failed receipt with current timestamp."""
        return cls(
            status="failed",
            timestamp=timestamp or datetime.now(UTC),
            reference=reference,
        )
