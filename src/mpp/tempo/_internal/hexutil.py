"""Hex and byte helpers matching ox's ``Hex`` conventions."""

from __future__ import annotations

import re
from typing import Any, Final

import rlp
from eth_utils.crypto import keccak as _keccak

_HEX_DIGITS: Final = re.compile(r"[0-9a-fA-F]*")


def to_bytes(value: str | bytes) -> bytes:
    """Decodes a ``0x``-prefixed hex string (odd lengths are left-padded)."""
    if isinstance(value, bytes):
        return value
    if not value.startswith(("0x", "0X")):
        raise ValueError(f"Hex value {value!r} must be 0x-prefixed.")
    digits = value[2:]
    if not _HEX_DIGITS.fullmatch(digits):
        raise ValueError(f"Hex value {value!r} is invalid.")
    if len(digits) % 2:
        digits = "0" + digits
    return bytes.fromhex(digits)


def to_hex(value: bytes) -> str:
    """Encodes bytes as a lowercase ``0x``-prefixed hex string."""
    return "0x" + value.hex()


def uint_to_bytes(value: int) -> bytes:
    """Minimal big-endian encoding of a non-negative integer (``0`` -> ``b""``)."""
    if value < 0:
        raise ValueError(f"Expected a non-negative integer, got {value}.")
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def bytes_to_uint(value: bytes) -> int:
    return int.from_bytes(value, "big")


def int_to_hex(value: int) -> str:
    """Formats an integer like ox ``Hex.fromNumber`` (``0`` -> ``"0x0"``)."""
    return hex(value)


def keccak256(value: bytes) -> bytes:
    return _keccak(value)


def rlp_encode(value: Any) -> bytes:
    """RLP-encodes nested lists of ``bytes``."""
    return bytes(rlp.encode(value))


def rlp_decode(value: bytes) -> Any:
    """RLP-decodes into nested lists of ``bytes``."""
    return rlp.decode(value)
