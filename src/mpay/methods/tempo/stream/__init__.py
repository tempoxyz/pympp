"""Tempo stream payment intent — pay-as-you-go payment channels.

Uses cumulative vouchers over an on-chain escrow contract for
incremental micropayments without per-request transactions.
"""

from mpay.methods.tempo.stream.errors import (
    AmountExceedsDepositError,
    ChannelClosedError,
    ChannelConflictError,
    ChannelNotFoundError,
    DeltaTooSmallError,
    InsufficientBalanceError,
    InvalidSignatureError,
    StreamError,
)
from mpay.methods.tempo.stream.receipt import (
    create_stream_receipt,
    deserialize_stream_receipt,
    serialize_stream_receipt,
)
from mpay.methods.tempo.stream.storage import (
    ChannelState,
    ChannelStorage,
    MemoryStorage,
    SessionState,
)
from mpay.methods.tempo.stream.types import (
    SignedVoucher,
    StreamReceipt,
    Voucher,
)
from mpay.methods.tempo.stream.voucher import sign_voucher, verify_voucher

__all__ = [
    "AmountExceedsDepositError",
    "ChannelClosedError",
    "ChannelConflictError",
    "ChannelNotFoundError",
    "ChannelState",
    "ChannelStorage",
    "DeltaTooSmallError",
    "InsufficientBalanceError",
    "InvalidSignatureError",
    "MemoryStorage",
    "SessionState",
    "SignedVoucher",
    "StreamError",
    "StreamReceipt",
    "Voucher",
    "create_stream_receipt",
    "deserialize_stream_receipt",
    "serialize_stream_receipt",
    "sign_voucher",
    "verify_voucher",
]
