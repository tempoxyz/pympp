"""Payment error types with RFC 9457 Problem Details support.

All payment errors can be converted to RFC 9457 Problem Details format
for structured error responses.
"""

from __future__ import annotations

import re
from typing import Any

_BASE_URI = "https://paymentauth.org/problems"


def _to_slug(name: str) -> str:
    """CamelCaseError → kebab-case slug (e.g. InvalidPayloadError → invalid-payload)."""
    name = name.removesuffix("Error")
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", name).lower()


def _to_title(name: str) -> str:
    """CamelCaseError → human-readable title (e.g. InvalidPayloadError → Invalid Payload)."""
    name = name.removesuffix("Error")
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)


class PaymentError(Exception):
    """Base class for all payment-related errors."""

    status: int = 402
    title: str = "Payment Error"

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if "type" not in cls.__dict__:
            cls.type = f"{_BASE_URI}/{_to_slug(cls.__name__)}"
        if "title" not in cls.__dict__:
            cls.title = _to_title(cls.__name__)

    type: str = f"{_BASE_URI}/payment-error"

    def to_problem_details(self, challenge_id: str | None = None) -> dict[str, Any]:
        """Convert to RFC 9457 Problem Details format."""
        details: dict[str, Any] = {
            "type": self.type,
            "title": self.title,
            "status": self.status,
            "detail": str(self),
        }
        if challenge_id is not None:
            details["challengeId"] = challenge_id
        return details


class PaymentRequiredError(PaymentError):
    """No credential was provided but payment is required."""

    def __init__(self, realm: str | None = None, description: str | None = None) -> None:
        parts = ["Payment is required"]
        if realm:
            parts.append(f'for "{realm}"')
        if description:
            parts.append(f"({description})")
        super().__init__(f"{' '.join(parts)}.")


class MalformedCredentialError(PaymentError):
    """Credential is malformed (invalid base64url, bad JSON structure)."""

    def __init__(self, reason: str | None = None) -> None:
        msg = f"Credential is malformed: {reason}." if reason else "Credential is malformed."
        super().__init__(msg)


class InvalidChallengeError(PaymentError):
    """Challenge ID is unknown, expired, or already used."""

    def __init__(self, challenge_id: str | None = None, reason: str | None = None) -> None:
        id_part = f' "{challenge_id}"' if challenge_id else ""
        reason_part = f": {reason}" if reason else ""
        super().__init__(f"Challenge{id_part} is invalid{reason_part}.")


class VerificationFailedError(PaymentError):
    """Payment proof is invalid or verification failed."""

    def __init__(self, reason: str | None = None) -> None:
        msg = (
            f"Payment verification failed: {reason}." if reason else "Payment verification failed."
        )
        super().__init__(msg)


class PaymentExpiredError(PaymentError):
    """Payment has expired."""

    def __init__(self, expires: str | None = None) -> None:
        msg = f"Payment expired at {expires}." if expires else "Payment has expired."
        super().__init__(msg)


class InvalidPayloadError(PaymentError):
    """Credential payload does not match the expected schema."""

    def __init__(self, reason: str | None = None) -> None:
        msg = (
            f"Credential payload is invalid: {reason}."
            if reason
            else "Credential payload is invalid."
        )
        super().__init__(msg)


class BadRequestError(PaymentError):
    """Request is malformed or contains invalid parameters."""

    status = 400

    def __init__(self, reason: str | None = None) -> None:
        msg = f"Bad request: {reason}." if reason else "Bad request."
        super().__init__(msg)


class PaymentInsufficientError(PaymentError):
    """Payment amount is insufficient (too low)."""

    def __init__(self, reason: str | None = None) -> None:
        msg = (
            f"Payment insufficient: {reason}." if reason else "Payment amount is insufficient."
        )
        super().__init__(msg)


class PaymentMethodUnsupportedError(PaymentError):
    """Payment method is not supported by the server."""

    status = 400
    type = f"{_BASE_URI}/method-unsupported"
    title = "Method Unsupported"

    def __init__(self, method: str | None = None) -> None:
        msg = (
            f'Payment method "{method}" is not supported.'
            if method
            else "Payment method is not supported."
        )
        super().__init__(msg)


class PaymentActionRequiredError(PaymentError):
    """Payment requires additional action (e.g., 3DS authentication)."""

    def __init__(self, reason: str | None = None) -> None:
        msg = (
            f"Payment requires action: {reason}." if reason else "Payment requires action."
        )
        super().__init__(msg)
