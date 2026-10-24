"""Base64 JSON codecs for x402 HTTP headers.

x402 encodes header bodies as standard base64 over JSON, unlike the Payment
auth scheme's base64url/JCS encoding (mppx ``src/internal/HeaderCodec.ts``).
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from typing import Any, TypeVar

from mpp.x402._types import (
    PaymentPayload,
    PaymentRequired,
    SettleResponse,
    X402FormatError,
    parse_payment_payload,
    parse_payment_required,
    parse_settle_response,
)

T = TypeVar("T")

MAX_HEADER_SIZE = 64 * 1024
"""Largest x402 header value decoded, matching the Payment credential bound."""


class InvalidHeaderError(X402FormatError):
    """A header value is not valid base64-encoded JSON of the expected shape."""

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(
            f"Invalid base64 JSON header: {reason}" if reason else "Invalid base64 JSON header"
        )


def _encode(value: Any) -> str:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _decode(value: str, parse: Callable[[Any], T]) -> T:
    if not isinstance(value, str) or len(value) > MAX_HEADER_SIZE:
        raise InvalidHeaderError("header is missing or too large")
    text = value.strip()
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
        decoded = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError) as error:
        raise InvalidHeaderError() from error
    try:
        return parse(decoded)
    except X402FormatError as error:
        raise InvalidHeaderError(str(error)) from error


def encode_payment_required(value: PaymentRequired) -> str:
    """Encode an x402 payment-required object for ``PAYMENT-REQUIRED``."""
    return _encode(parse_payment_required(value))


def decode_payment_required(value: str) -> PaymentRequired:
    """Decode and validate a ``PAYMENT-REQUIRED`` header value."""
    return _decode(value, parse_payment_required)


def encode_payment_signature(value: PaymentPayload) -> str:
    """Encode an x402 payment payload for ``PAYMENT-SIGNATURE``."""
    return _encode(parse_payment_payload(value))


def decode_payment_signature(value: str) -> PaymentPayload:
    """Decode and validate a ``PAYMENT-SIGNATURE`` header value."""
    return _decode(value, parse_payment_payload)


def encode_payment_response(value: SettleResponse) -> str:
    """Encode an x402 settlement response for ``PAYMENT-RESPONSE``."""
    return _encode(parse_settle_response(value))


def decode_payment_response(value: str) -> SettleResponse:
    """Decode and validate a ``PAYMENT-RESPONSE`` header value."""
    return _decode(value, parse_settle_response)
