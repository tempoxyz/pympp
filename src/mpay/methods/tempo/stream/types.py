"""Core types for stream payments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Voucher:
    """Voucher for cumulative payment.

    Cumulative monotonicity prevents replay attacks.
    """

    channel_id: str  # 0x-prefixed bytes32 hex
    cumulative_amount: int  # uint128


@dataclass(frozen=True)
class SignedVoucher(Voucher):
    """Signed voucher with EIP-712 signature."""

    signature: str  # 0x-prefixed 65-byte hex


@dataclass
class StreamReceipt:
    """Stream receipt returned in Payment-Receipt header."""

    method: str
    intent: str
    status: str
    timestamp: str  # ISO 8601
    reference: str  # channelId — satisfies Receipt contract
    challenge_id: str
    channel_id: str
    accepted_cumulative: str  # decimal string
    spent: str  # decimal string
    units: int | None = None
    tx_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to camelCase dict for JSON encoding."""
        d: dict[str, Any] = {
            "method": self.method,
            "intent": self.intent,
            "status": self.status,
            "timestamp": self.timestamp,
            "reference": self.reference,
            "challengeId": self.challenge_id,
            "channelId": self.channel_id,
            "acceptedCumulative": self.accepted_cumulative,
            "spent": self.spent,
        }
        if self.units is not None:
            d["units"] = self.units
        if self.tx_hash is not None:
            d["txHash"] = self.tx_hash
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> StreamReceipt:
        """Deserialize from camelCase dict."""
        return cls(
            method=d["method"],
            intent=d["intent"],
            status=d["status"],
            timestamp=d["timestamp"],
            reference=d["reference"],
            challenge_id=d["challengeId"],
            channel_id=d["channelId"],
            accepted_cumulative=d["acceptedCumulative"],
            spent=d["spent"],
            units=d.get("units"),
            tx_hash=d.get("txHash"),
        )
