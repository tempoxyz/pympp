"""Stream receipt creation and serialization."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

from mpay.methods.tempo.stream.types import StreamReceipt


def create_stream_receipt(
    *,
    challenge_id: str,
    channel_id: str,
    accepted_cumulative: int,
    spent: int,
    units: int | None = None,
    tx_hash: str | None = None,
) -> StreamReceipt:
    """Create a stream receipt.

    Args:
        challenge_id: Challenge identifier.
        channel_id: Payment channel identifier (0x-prefixed bytes32).
        accepted_cumulative: Highest cumulative amount accepted (int).
        spent: Total amount charged/spent (int).
        units: Number of units charged.
        tx_hash: Transaction hash (for close action).

    Returns:
        A StreamReceipt instance.
    """
    return StreamReceipt(
        method="tempo",
        intent="stream",
        status="success",
        timestamp=datetime.now(UTC).isoformat(),
        reference=channel_id,
        challenge_id=challenge_id,
        channel_id=channel_id,
        accepted_cumulative=str(accepted_cumulative),
        spent=str(spent),
        units=units,
        tx_hash=tx_hash,
    )


def serialize_stream_receipt(receipt: StreamReceipt) -> str:
    """Serialize a stream receipt to base64url JSON (no padding).

    This format is used in the Payment-Receipt header.
    """
    json_str = json.dumps(receipt.to_dict(), separators=(",", ":"))
    return base64.urlsafe_b64encode(json_str.encode()).rstrip(b"=").decode()


def deserialize_stream_receipt(encoded: str) -> StreamReceipt:
    """Deserialize a Payment-Receipt header value to a StreamReceipt."""
    # Add back padding
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    json_str = base64.urlsafe_b64decode(encoded).decode()
    return StreamReceipt.from_dict(json.loads(json_str))
