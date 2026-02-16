"""Payment error types with RFC 9457 Problem Details support.

All payment errors can be converted to RFC 9457 Problem Details format
for structured error responses.
"""

from __future__ import annotations

from typing import Any

_BASE_URI = "https://paymentauth.org/problems"


class PaymentError(Exception):
    """Base class for all payment-related errors."""

    type: str = f"{_BASE_URI}/payment-error"
    status: int = 402

    def to_problem_details(self, challenge_id: str | None = None) -> dict[str, Any]:
        """Convert to RFC 9457 Problem Details format."""
        details: dict[str, Any] = {
            "type": self.type,
            "title": type(self).__name__,
            "status": self.status,
            "detail": str(self),
        }
        if challenge_id:
            details["challengeId"] = challenge_id
        return details


class PaymentRequiredError(PaymentError):
    """No credential was provided but payment is required."""

    type = f"{_BASE_URI}/payment-required"

    def __init__(self, realm: str | None = None, description: str | None = None) -> None:
        parts = ["Payment is required"]
        if realm:
            parts.append(f'for "{realm}"')
        if description:
            parts.append(f"({description})")
        super().__init__(f"{' '.join(parts)}.")


class MalformedCredentialError(PaymentError):
    """Credential is malformed (invalid base64url, bad JSON structure)."""

    type = f"{_BASE_URI}/malformed-credential"

    def __init__(self, reason: str | None = None) -> None:
        msg = f"Credential is malformed: {reason}." if reason else "Credential is malformed."
        super().__init__(msg)


class InvalidChallengeError(PaymentError):
    """Challenge ID is unknown, expired, or already used."""

    type = f"{_BASE_URI}/invalid-challenge"

    def __init__(self, id: str | None = None, reason: str | None = None) -> None:
        id_part = f' "{id}"' if id else ""
        reason_part = f": {reason}" if reason else ""
        super().__init__(f"Challenge{id_part} is invalid{reason_part}.")


class VerificationFailedError(PaymentError):
    """Payment proof is invalid or verification failed."""

    type = f"{_BASE_URI}/verification-failed"

    def __init__(self, reason: str | None = None) -> None:
        msg = (
            f"Payment verification failed: {reason}." if reason else "Payment verification failed."
        )
        super().__init__(msg)


class PaymentExpiredError(PaymentError):
    """Payment has expired."""

    type = f"{_BASE_URI}/payment-expired"

    def __init__(self, expires: str | None = None) -> None:
        msg = f"Payment expired at {expires}." if expires else "Payment has expired."
        super().__init__(msg)


class InvalidPayloadError(PaymentError):
    """Credential payload does not match the expected schema."""

    type = f"{_BASE_URI}/invalid-payload"

    def __init__(self, reason: str | None = None) -> None:
        msg = (
            f"Credential payload is invalid: {reason}."
            if reason
            else "Credential payload is invalid."
        )
        super().__init__(msg)
