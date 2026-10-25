"""x402 header codecs: standard base64 of compact JSON (``JSON.stringify``) bodies."""

import base64
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from pydantic import BaseModel, ValidationError

from mpp import _base64url, _json
from mpp.x402._types import Extension, PaymentPayload, PaymentRequired, ResourceInfo, SettleResponse

MAX_HEADER_SIZE: Final = 64 * 1024
"""Largest x402 header value decoded, matching the Payment credential bound."""
MAX_JSON_DEPTH: Final = 64
"""Deepest JSON nesting accepted in an x402 header."""
_MAX_SAFE_INTEGER: Final = 2**53 - 1


class InvalidJsonHeaderError(ValueError):
    """A JSON header value is not valid base64-encoded JSON (or fails schema validation).

    Attributes:
        reason: What is wrong with the value, when known.
    """

    def __init__(self, reason: str | None = None) -> None:
        self.reason = reason
        super().__init__("Invalid base64 JSON header.")


def _encode[M: BaseModel](model: type[M], value: M | Mapping[str, Any]) -> str:
    parsed = value if isinstance(value, model) else model.model_validate(value)
    body = _json.dumps(parsed.model_dump(mode="json", by_alias=True, exclude_none=True))
    return base64.b64encode(body.encode()).decode("ascii")


def _decode_json(value: str) -> Any:
    if len(value) > MAX_HEADER_SIZE:
        raise InvalidJsonHeaderError("header is too large")
    try:
        decoded = _json.loads(_base64url.decode_text(value.strip()))
        _assert_canonicalizable(decoded)
    except (ValueError, RecursionError) as error:
        raise InvalidJsonHeaderError() from error
    return decoded


def _assert_canonicalizable(value: Any) -> None:
    """Rejects JSON RFC 8785 cannot canonicalize (route binding hashes echoed values that way).

    That is deep nesting, lone UTF-16 surrogates (which break any later UTF-8 encoding, such as
    echoing the value in an error header), integers beyond 2**53 and non-finite numbers.
    """
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON is nested too deeply")
        if isinstance(item, str):
            item.encode()
        elif isinstance(item, bool) or item is None:
            continue
        elif isinstance(item, int):
            if abs(item) > _MAX_SAFE_INTEGER:
                raise ValueError("JSON integer is out of range")
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("JSON number is not finite")
        elif isinstance(item, dict):
            for key, child in item.items():
                key.encode()
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _decode[M: BaseModel](model: type[M], value: str) -> M:
    record = _decode_json(value)
    try:
        return model.model_validate(record)
    except ValidationError as error:
        raise InvalidJsonHeaderError(_validation_reason(record, error)) from error


def _validation_reason(record: Any, error: ValidationError) -> str:
    if isinstance(record, dict) and "x402Version" in record and record["x402Version"] != 2:
        return "x402Version must be 2"
    first = error.errors()[0]
    location = ".".join(str(part) for part in first["loc"])
    return f"{location}: {first['msg']}" if location else first["msg"]


def encode_payment_required(payment_required: PaymentRequired | Mapping[str, Any]) -> str:
    """Encodes an x402 payment-required object for the ``PAYMENT-REQUIRED`` header."""
    return _encode(PaymentRequired, payment_required)


def decode_payment_required(value: str) -> PaymentRequired:
    """Decodes a ``PAYMENT-REQUIRED`` header value.

    Raises:
        InvalidJsonHeaderError: When the value is not valid base64 JSON of the right shape.
    """
    return _decode(PaymentRequired, value)


def encode_payment_signature(payment_payload: PaymentPayload | Mapping[str, Any]) -> str:
    """Encodes an x402 payment payload for the ``PAYMENT-SIGNATURE`` header."""
    return _encode(PaymentPayload, payment_payload)


def decode_payment_signature(value: str) -> PaymentPayload:
    """Decodes a ``PAYMENT-SIGNATURE`` header value.

    Raises:
        InvalidJsonHeaderError: When the value is not valid base64 JSON of the right shape.
    """
    return _decode(PaymentPayload, value)


def encode_payment_response(payment_response: SettleResponse | Mapping[str, Any]) -> str:
    """Encodes an x402 settlement response for the ``PAYMENT-RESPONSE`` header."""
    return _encode(SettleResponse, payment_response)


def decode_payment_response(value: str) -> SettleResponse:
    """Decodes a ``PAYMENT-RESPONSE`` header value.

    Raises:
        InvalidJsonHeaderError: When the value is not valid base64 JSON of the right shape.
    """
    return _decode(SettleResponse, value)


@dataclass(frozen=True, slots=True, kw_only=True)
class PaymentRequiredEnvelope:
    """Tolerant ``PAYMENT-REQUIRED`` envelope: ``accepts`` entries are left unvalidated."""

    accepts: list[Any]
    resource: ResourceInfo
    extensions: dict[str, Extension] | None = None
    x402_version: int = 2


def decode_payment_required_envelope(value: str) -> PaymentRequiredEnvelope:
    """Decodes only the ``PAYMENT-REQUIRED`` envelope so unsupported accepts can be filtered.

    Invalid ``extensions`` are dropped rather than rejected.

    Raises:
        InvalidJsonHeaderError: When the envelope itself is malformed.
    """
    record = _decode_json(value)
    try:
        if not isinstance(record, dict):
            raise ValueError("Expected an object.")
        if record.get("x402Version") != 2 or not isinstance(record.get("accepts"), list):
            raise ValueError("Unsupported x402 envelope.")
        resource = ResourceInfo.model_validate(record.get("resource"))
        extensions: dict[str, Extension] | None = None
        if record.get("extensions") is not None:
            try:
                raw = record["extensions"]
                if not isinstance(raw, dict):
                    raise ValueError("Invalid extensions.")
                extensions = {key: Extension.model_validate(item) for key, item in raw.items()}
            except (ValueError, ValidationError):
                extensions = None
        return PaymentRequiredEnvelope(
            accepts=record["accepts"], resource=resource, extensions=extensions
        )
    except (ValueError, ValidationError) as error:
        raise InvalidJsonHeaderError() from error
