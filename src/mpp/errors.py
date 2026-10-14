"""Payment error types with RFC 9457 Problem Details support.

All payment errors can be converted to RFC 9457 Problem Details format
for structured error responses.
"""

from __future__ import annotations

import re
from typing import Any

_BASE_URI = "https://paymentauth.org/problems"


class Hints:
    """Default hint messages for payment errors."""

    payment_required = (
        "Use a supported wallet to pay for this resource using one of the supported "
        "payment methods returned in the WWW-Authenticate header. "
        "See https://mpp.dev/tools/wallet.md"
    )
    malformed_credential = (
        "Use a supported wallet to construct valid credentials for one of the supported "
        "payment methods returned in the WWW-Authenticate header. "
        "See https://mpp.dev/tools/wallet.md"
    )
    method_unsupported = payment_required


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
    hint: str | None = None
    details: dict[str, Any] | None = None
    """Machine-readable details safe to expose in problem details output."""
    retry_challenge: Any | None = None
    """Fresh :class:`~mpp.Challenge` attached by the server verification flow
    when payment fails, so transports can return a retryable 402 response."""

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
        if self.hint is not None:
            details["hint"] = self.hint
        if self.details is not None:
            details["details"] = self.details
        return details


class PaymentOutcomeUnknownError(PaymentError, RuntimeError):
    """A credential was sent, but the payment result could not be confirmed."""

    def __init__(
        self,
        challenge: Any,
        cause: BaseException,
        *,
        credential: Any = None,
        request: Any = None,
    ) -> None:
        self.challenge = challenge
        self.cause = cause
        self.credential = credential
        self.request = request
        super().__init__(
            "Payment outcome is unknown after sending a credential "
            f"for challenge {challenge.id}. Do not blindly retry."
        )


class PaymentRequiredError(PaymentError):
    """No credential was provided but payment is required."""

    hint = Hints.payment_required

    def __init__(self, realm: str | None = None, description: str | None = None) -> None:
        parts = ["Payment is required"]
        if realm:
            parts.append(f'for "{realm}"')
        if description:
            parts.append(f"({description})")
        super().__init__(f"{' '.join(parts)}.")


class MalformedCredentialError(PaymentError):
    """Credential is malformed (invalid base64url, bad JSON structure)."""

    hint = Hints.malformed_credential

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

    def __init__(
        self,
        reason: str | None = None,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        msg = (
            f"Payment verification failed: {reason}." if reason else "Payment verification failed."
        )
        super().__init__(msg)
        self.details = details


class InternalPaymentError(PaymentError):
    """Payment processing failed because of an unexpected internal error.

    Used for infrastructure or configuration failures (for example an
    unreachable RPC node, or any failure after a transaction was broadcast)
    where the payment may already have landed. Servers must not answer this
    with a retryable 402 challenge, since that would invite the client to pay
    again.

    The message is always generic. Raise it ``from`` the original exception:
    the cause is kept on ``__cause__`` for server-side logging and hooks and
    never appears in problem details.
    """

    status = 500
    type = f"{_BASE_URI}/internal-payment-error"
    title = "Internal Payment Error"

    def __init__(self) -> None:
        super().__init__("An internal payment error occurred.")


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
        msg = f"Payment insufficient: {reason}." if reason else "Payment amount is insufficient."
        super().__init__(msg)


class PaymentMethodUnsupportedError(PaymentError):
    """Payment method is not supported by the server."""

    status = 400
    type = f"{_BASE_URI}/method-unsupported"
    title = "Method Unsupported"
    hint = Hints.method_unsupported

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
        msg = f"Payment requires action: {reason}." if reason else "Payment requires action."
        super().__init__(msg)


class VerificationError(VerificationFailedError):
    """Payment verification failed.

    Raised by payment intents when a credential is invalid. Unlike
    :class:`VerificationFailedError`, the message is used verbatim.
    """

    type = VerificationFailedError.type
    title = VerificationFailedError.title

    def __init__(
        self,
        message: str = "Payment verification failed.",
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        PaymentError.__init__(self, message)
        self.details = details


class CredentialReplayedError(VerificationError):
    """Credential was already used to settle a payment.

    Shares the verification-failed status and problem type, so the response
    is the same as for any other verification failure.
    """

    type = VerificationFailedError.type
    title = VerificationFailedError.title

    def __init__(
        self,
        reason: str = "Credential has already been used",
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        VerificationFailedError.__init__(self, reason, details=details)
