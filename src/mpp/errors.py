"""Payment errors rendered as RFC 9457 Problem Details (same types/titles/statuses as mppx)."""

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar

__all__ = [
    "HINT_MALFORMED_CREDENTIAL",
    "HINT_METHOD_UNSUPPORTED",
    "HINT_PAYMENT_REQUIRED",
    "AmountExceedsDepositError",
    "BadRequestError",
    "ChannelClosedError",
    "ChannelNotFoundError",
    "CredentialReplayedError",
    "DeltaTooSmallError",
    "InsufficientBalanceError",
    "InternalPaymentError",
    "InvalidChallengeError",
    "InvalidPayloadError",
    "InvalidSignatureError",
    "MalformedCredentialError",
    "PaymentActionRequiredError",
    "PaymentError",
    "PaymentExpiredError",
    "PaymentInsufficientError",
    "PaymentMethodUnsupportedError",
    "PaymentOutcomeUnknownError",
    "PaymentRequiredError",
    "SignerMismatchError",
    "VerificationFailedError",
]


if TYPE_CHECKING:
    from mpp.challenge import Challenge

_WALLET_HINT = (
    "Use a supported wallet to pay for this resource using one of the supported payment "
    "methods returned in the WWW-Authenticate header. See https://mpp.dev/tools/wallet.md"
)

HINT_PAYMENT_REQUIRED = _WALLET_HINT
HINT_MALFORMED_CREDENTIAL = (
    "Use a supported wallet to construct valid credentials for one of the supported payment "
    "methods returned in the WWW-Authenticate header. See https://mpp.dev/tools/wallet.md"
)
HINT_METHOD_UNSUPPORTED = _WALLET_HINT

_PROBLEMS = "https://paymentauth.org/problems"


class PaymentError(Exception):
    """Base class for all payment errors.

    Subclasses define the RFC 9457 ``type`` URI, ``title`` and HTTP ``status``. ``details`` holds
    safe method-specific diagnostic context that is serialized into Problem Details; ``cause``
    (``__cause__``) never is.
    """

    type: ClassVar[str]
    title: ClassVar[str]
    status: ClassVar[int] = 402
    hint: ClassVar[str | None] = None

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.details: Mapping[str, Any] | None = details
        if cause is not None:
            self.__cause__ = cause

    @property
    def message(self) -> str:
        """Human-readable explanation (Problem Details ``detail``)."""
        return str(self.args[0]) if self.args else ""

    @property
    def name(self) -> str:
        """Error class name (mirrors JavaScript ``Error.name``)."""
        return type(self).__name__

    def to_problem_details(self, challenge_id: str | None = None) -> dict[str, Any]:
        """Converts the error to an RFC 9457 Problem Details object."""
        problem: dict[str, Any] = {
            "type": self.type,
            "title": self.title,
            "status": self.status,
            "detail": self.message,
        }
        if self.details:
            problem["details"] = dict(self.details)
        if self.hint:
            problem["hint"] = self.hint
        if challenge_id:
            problem["challengeId"] = challenge_id
        return problem


class MalformedCredentialError(PaymentError):
    """Credential is malformed (invalid base64url, bad JSON structure)."""

    type = f"{_PROBLEMS}/malformed-credential"
    title = "Malformed Credential"
    hint = HINT_MALFORMED_CREDENTIAL

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(
            f"Credential is malformed: {reason}." if reason else "Credential is malformed."
        )


class InvalidChallengeError(PaymentError):
    """Challenge ID is unknown, expired, or already used."""

    type = f"{_PROBLEMS}/invalid-challenge"
    title = "Invalid Challenge"

    def __init__(self, *, id: str | None = None, reason: str | None = None) -> None:
        id_part = f' "{id}"' if id else ""
        reason_part = f": {reason}" if reason else ""
        super().__init__(f"Challenge{id_part} is invalid{reason_part}.")


class VerificationFailedError(PaymentError):
    """Payment proof is invalid or verification failed."""

    type = f"{_PROBLEMS}/verification-failed"
    title = "Verification Failed"

    def __init__(
        self, *, reason: str | None = None, details: Mapping[str, Any] | None = None
    ) -> None:
        super().__init__(
            f"Payment verification failed: {reason}." if reason else "Payment verification failed.",
            details=details,
        )


class CredentialReplayedError(VerificationFailedError):
    """The payment behind a credential is already used or bound elsewhere.

    Answered with 403 and no challenge, since a fresh 402 would invite an auto-paying client to
    pay again. The problem type stays ``verification-failed``.
    """

    status = 403

    def __init__(self, *, reason: str = "Credential has already been used") -> None:
        super().__init__(reason=reason)


class InternalPaymentError(PaymentError):
    """Payment processing failed because of an unexpected internal error.

    The response stays generic; the original error is only available on ``__cause__``.
    """

    type = f"{_PROBLEMS}/internal-payment-error"
    title = "Internal Payment Error"
    status = 500

    def __init__(self, *, cause: BaseException | None = None) -> None:
        super().__init__("An internal payment error occurred.", cause=cause)


class PaymentActionRequiredError(PaymentError):
    """Payment requires additional action (e.g., 3DS authentication)."""

    type = f"{_PROBLEMS}/payment-action-required"
    title = "Payment Action Required"

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(
            f"Payment requires action: {reason}." if reason else "Payment requires action."
        )


class PaymentExpiredError(PaymentError):
    """Payment has expired."""

    type = f"{_PROBLEMS}/payment-expired"
    title = "Payment Expired"

    def __init__(self, *, expires: str | None = None) -> None:
        super().__init__(f"Payment expired at {expires}." if expires else "Payment has expired.")


class PaymentOutcomeUnknownError(PaymentError):
    """A credential was sent, but the payment result could not be confirmed.

    Reconcile with ``credential`` (and ``transaction_hash`` when derivable) instead of retrying,
    which could pay twice.
    """

    type = f"{_PROBLEMS}/payment-outcome-unknown"
    title = "Payment Outcome Unknown"

    def __init__(
        self,
        *,
        challenge: "Challenge",
        credential: str,
        transaction_hash: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(
            f'Payment outcome is unknown after sending a credential for challenge "{challenge.id}". '
            "Do not blindly retry.",
            cause=cause,
        )
        self.challenge = challenge
        self.credential = credential
        self.transaction_hash = transaction_hash


class PaymentRequiredError(PaymentError):
    """No credential was provided but payment is required."""

    type = f"{_PROBLEMS}/payment-required"
    title = "Payment Required"
    hint = HINT_PAYMENT_REQUIRED

    def __init__(self, *, description: str | None = None) -> None:
        parts = ["Payment is required"]
        if description:
            parts.append(f"({description})")
        super().__init__(f"{' '.join(parts)}.")


class InvalidPayloadError(PaymentError):
    """Credential payload does not match the expected schema."""

    type = f"{_PROBLEMS}/invalid-payload"
    title = "Invalid Payload"

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(
            f"Credential payload is invalid: {reason}."
            if reason
            else "Credential payload is invalid."
        )


class BadRequestError(PaymentError):
    """Request is malformed or contains invalid parameters."""

    type = f"{_PROBLEMS}/bad-request"
    title = "Bad Request"
    status = 400

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(f"Bad request: {reason}." if reason else "Bad request.")


class PaymentInsufficientError(PaymentError):
    """Payment amount is insufficient (too low)."""

    type = f"{_PROBLEMS}/payment-insufficient"
    title = "Payment Insufficient"

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(
            f"Payment insufficient: {reason}." if reason else "Payment amount is insufficient."
        )


class PaymentMethodUnsupportedError(PaymentError):
    """Payment method is not supported by the server."""

    type = f"{_PROBLEMS}/method-unsupported"
    title = "Method Unsupported"
    status = 400
    hint = HINT_METHOD_UNSUPPORTED

    def __init__(self, *, method: str | None = None) -> None:
        super().__init__(
            f'Payment method "{method}" is not supported.'
            if method
            else "Payment method is not supported."
        )


class InsufficientBalanceError(PaymentError):
    """Insufficient balance in the payment channel."""

    type = f"{_PROBLEMS}/session/insufficient-balance"
    title = "Insufficient Balance"

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(f"Insufficient balance: {reason}." if reason else "Insufficient balance.")


class InvalidSignatureError(PaymentError):
    """Voucher or close request signature is invalid."""

    type = f"{_PROBLEMS}/session/invalid-signature"
    title = "Invalid Signature"

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(f"Invalid signature: {reason}." if reason else "Invalid signature.")


class SignerMismatchError(PaymentError):
    """Recovered signer is not authorized for this channel."""

    type = f"{_PROBLEMS}/session/signer-mismatch"
    title = "Signer Mismatch"

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(
            f"Signer mismatch: {reason}."
            if reason
            else "Signer is not authorized for this channel."
        )


class AmountExceedsDepositError(PaymentError):
    """Voucher cumulative amount exceeds the channel deposit."""

    type = f"{_PROBLEMS}/session/amount-exceeds-deposit"
    title = "Amount Exceeds Deposit"

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(
            f"Amount exceeds deposit: {reason}."
            if reason
            else "Voucher amount exceeds channel deposit."
        )


class DeltaTooSmallError(PaymentError):
    """Voucher amount increase is below the minimum delta."""

    type = f"{_PROBLEMS}/session/delta-too-small"
    title = "Delta Too Small"

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(
            f"Delta too small: {reason}."
            if reason
            else "Amount increase below minimum voucher delta."
        )


class ChannelNotFoundError(PaymentError):
    """No channel with this ID exists."""

    type = f"{_PROBLEMS}/session/channel-not-found"
    title = "Channel Not Found"
    status = 410

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(
            f"Channel not found: {reason}." if reason else "No channel with this ID exists."
        )


class ChannelClosedError(PaymentError):
    """Channel is closed or finalized."""

    type = f"{_PROBLEMS}/session/channel-finalized"
    title = "Channel Closed"
    status = 410

    def __init__(self, *, reason: str | None = None) -> None:
        super().__init__(f"Channel closed: {reason}." if reason else "Channel is closed.")
