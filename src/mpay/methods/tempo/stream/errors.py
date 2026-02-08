"""Stream-specific error types.

Each error maps to an RFC 9457 Problem Details type URI
and an appropriate HTTP status code.
"""

from __future__ import annotations

from typing import Any


class StreamError(Exception):
    """Base class for stream payment errors."""

    status: int = 402
    type: str = "https://paymentauth.org/problems/stream/error"

    def __init__(self, reason: str | None = None) -> None:
        self.reason = reason
        super().__init__(reason or self.__class__.__doc__ or "Stream error")

    def to_problem_details(self, challenge_id: str | None = None) -> dict[str, Any]:
        """Convert to RFC 9457 Problem Details format."""
        d: dict[str, Any] = {
            "type": self.type,
            "title": self.__class__.__name__,
            "status": self.status,
            "detail": str(self),
        }
        if challenge_id:
            d["challengeId"] = challenge_id
        return d


class InsufficientBalanceError(StreamError):
    """Insufficient balance in the payment channel."""

    status = 402
    type = "https://paymentauth.org/problems/stream/insufficient-balance"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason or "Insufficient balance")


class InvalidSignatureError(StreamError):
    """Voucher or close request signature is invalid."""

    status = 402
    type = "https://paymentauth.org/problems/stream/invalid-signature"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason or "Invalid signature")


class AmountExceedsDepositError(StreamError):
    """Voucher cumulative amount exceeds the channel deposit."""

    status = 402
    type = "https://paymentauth.org/problems/stream/amount-exceeds-deposit"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason or "Voucher amount exceeds channel deposit")


class DeltaTooSmallError(StreamError):
    """Voucher amount increase is below the minimum delta."""

    status = 402
    type = "https://paymentauth.org/problems/stream/delta-too-small"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason or "Amount increase below minimum voucher delta")


class ChannelNotFoundError(StreamError):
    """No channel with this ID exists."""

    status = 410
    type = "https://paymentauth.org/problems/stream/channel-not-found"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason or "No channel with this ID exists")


class ChannelClosedError(StreamError):
    """Channel is closed or finalized."""

    status = 410
    type = "https://paymentauth.org/problems/stream/channel-finalized"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason or "Channel is closed")


class ChannelConflictError(StreamError):
    """Conflict with existing channel state (e.g., concurrent stream)."""

    status = 409
    type = "https://paymentauth.org/problems/stream/channel-conflict"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason or "Channel conflict")
