"""x402 v2 wire types and validation.

Mirrors mppx's ``src/x402/Types.ts``: only x402 version 2 and the ``exact``
scheme on EVM networks are supported. Values are plain JSON dictionaries; the
``parse_*`` helpers validate untrusted input and raise :class:`X402FormatError`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Literal, NotRequired, TypedDict

X402_VERSION: Literal[2] = 2
"""x402 protocol version supported by this package."""

PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
"""HTTP header carrying a base64-encoded x402 payment-required response."""

PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
"""HTTP header carrying a base64-encoded x402 payment payload."""

PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"
"""HTTP header carrying a base64-encoded x402 settlement response."""

EXACT_SCHEME = "exact"
"""The only x402 scheme supported by this package."""

EIP3009 = "eip3009"
"""EIP-3009 ``transferWithAuthorization`` asset transfer method."""

SYNTHETIC_CHALLENGE_ID_PREFIX = "x402:"
"""Prefix of the local challenge IDs given to credentials converted from x402."""

# uint256 values have at most 78 digits.
_ATOMIC_AMOUNT_RE = re.compile(r"[0-9]{1,78}")
_EVM_NETWORK_RE = re.compile(r"eip155:[0-9]+")
_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_SIGNATURE_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})+")


class X402FormatError(ValueError):
    """An x402 value is not valid for the supported wire format."""


class ResourceInfo(TypedDict):
    """The protected resource described by an x402 v2 response."""

    url: str
    description: NotRequired[str]
    mimeType: NotRequired[str]


class PaymentRequirements(TypedDict):
    """x402 v2 payment requirements for the ``exact`` scheme."""

    scheme: Literal["exact"]
    network: str
    amount: str
    asset: str
    payTo: str
    maxTimeoutSeconds: int
    extra: NotRequired[dict[str, Any]]


class PaymentRequired(TypedDict):
    """x402 v2 payment-required response carried in ``PAYMENT-REQUIRED``."""

    x402Version: Literal[2]
    accepts: list[PaymentRequirements]
    resource: ResourceInfo
    error: NotRequired[str]
    extensions: NotRequired[dict[str, Any]]


class PaymentPayload(TypedDict):
    """x402 v2 payment payload carried in ``PAYMENT-SIGNATURE``."""

    x402Version: Literal[2]
    accepted: PaymentRequirements
    payload: dict[str, Any]
    resource: NotRequired[ResourceInfo]
    extensions: NotRequired[dict[str, Any]]


class VerifyResponse(TypedDict):
    """Facilitator ``/verify`` response."""

    isValid: bool
    invalidReason: NotRequired[str]
    invalidMessage: NotRequired[str]
    payer: NotRequired[str]


class SettleResponse(TypedDict):
    """Facilitator ``/settle`` response and ``PAYMENT-RESPONSE`` body."""

    success: bool
    transaction: str
    network: str
    payer: NotRequired[str]
    amount: NotRequired[str]
    errorReason: NotRequired[str]
    errorMessage: NotRequired[str]


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise X402FormatError(f"{name} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise X402FormatError(f"{name} keys must be strings")
    return dict(value)


def _string(record: Mapping[str, Any], key: str, name: str, *, non_empty: bool = True) -> str:
    value = record.get(key)
    if not isinstance(value, str) or (non_empty and not value):
        raise X402FormatError(f"{name}.{key} must be a non-empty string")
    return value


def _optional_string(record: Mapping[str, Any], key: str, name: str) -> str | None:
    value = record.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise X402FormatError(f"{name}.{key} must be a string")
    return value


def _pattern(record: Mapping[str, Any], key: str, name: str, pattern: re.Pattern[str]) -> str:
    value = _string(record, key, name)
    if not pattern.fullmatch(value):
        raise X402FormatError(f"{name}.{key} is malformed")
    return value


def _version(record: Mapping[str, Any], name: str) -> None:
    version = record.get("x402Version")
    if isinstance(version, bool) or version != X402_VERSION:
        raise X402FormatError(f"{name}.x402Version must be {X402_VERSION}")


def _extensions(record: Mapping[str, Any], name: str) -> None:
    value = record.get("extensions")
    if value is None:
        return
    for key, extension in _object(value, f"{name}.extensions").items():
        extension = _object(extension, f"{name}.extensions.{key}")
        _object(extension.get("info"), f"{name}.extensions.{key}.info")
        _object(extension.get("schema"), f"{name}.extensions.{key}.schema")


def parse_resource(value: Any, name: str = "resource") -> ResourceInfo:
    """Validate x402 resource information."""
    record = _object(value, name)
    _string(record, "url", name)
    for key in ("description", "mimeType", "serviceName", "iconUrl"):
        _optional_string(record, key, name)
    return record  # type: ignore[return-value]


def parse_payment_requirements(
    value: Any, name: str = "paymentRequirements"
) -> PaymentRequirements:
    """Validate x402 v2 ``exact`` EVM payment requirements."""
    record = _object(value, name)
    if record.get("scheme") != EXACT_SCHEME:
        raise X402FormatError(f"{name}.scheme must be {EXACT_SCHEME!r}")
    _pattern(record, "network", name, _EVM_NETWORK_RE)
    _pattern(record, "amount", name, _ATOMIC_AMOUNT_RE)
    _string(record, "asset", name)
    _string(record, "payTo", name)
    timeout = record.get("maxTimeoutSeconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int | float) or timeout <= 0:
        raise X402FormatError(f"{name}.maxTimeoutSeconds must be a positive number")
    if record.get("extra") is not None:
        _object(record["extra"], f"{name}.extra")
    return record  # type: ignore[return-value]


def parse_payment_required(value: Any) -> PaymentRequired:
    """Validate an x402 v2 payment-required response."""
    record = _object(value, "paymentRequired")
    _version(record, "paymentRequired")
    accepts = record.get("accepts")
    if not isinstance(accepts, list) or not accepts:
        raise X402FormatError("paymentRequired.accepts must be a non-empty array")
    for index, accepted in enumerate(accepts):
        parse_payment_requirements(accepted, f"paymentRequired.accepts[{index}]")
    parse_resource(record.get("resource"), "paymentRequired.resource")
    _optional_string(record, "error", "paymentRequired")
    _extensions(record, "paymentRequired")
    return record  # type: ignore[return-value]


def parse_eip3009_payload(value: Any, name: str = "payload") -> dict[str, Any]:
    """Validate an exact EVM EIP-3009 payload body."""
    record = _object(value, name)
    auth_name = f"{name}.authorization"
    authorization = _object(record.get("authorization"), auth_name)
    _pattern(authorization, "from", auth_name, _ADDRESS_RE)
    _pattern(authorization, "to", auth_name, _ADDRESS_RE)
    _pattern(authorization, "nonce", auth_name, _HASH_RE)
    for key in ("value", "validAfter", "validBefore"):
        _pattern(authorization, key, auth_name, _ATOMIC_AMOUNT_RE)
    _pattern(record, "signature", name, _SIGNATURE_RE)
    return record


def parse_payment_payload(value: Any) -> PaymentPayload:
    """Validate an x402 v2 payment payload.

    The ``payload`` body is only checked to be an object here; the EIP-3009
    shape is checked by :func:`parse_eip3009_payload` when it is converted,
    because the x402 ``exact`` scheme also defines Permit2 bodies.
    """
    record = _object(value, "paymentPayload")
    _version(record, "paymentPayload")
    parse_payment_requirements(record.get("accepted"), "paymentPayload.accepted")
    _object(record.get("payload"), "paymentPayload.payload")
    if record.get("resource") is not None:
        parse_resource(record["resource"], "paymentPayload.resource")
    _extensions(record, "paymentPayload")
    return record  # type: ignore[return-value]


def parse_verify_response(value: Any) -> VerifyResponse:
    """Validate a facilitator ``/verify`` response."""
    record = _object(value, "verifyResponse")
    if not isinstance(record.get("isValid"), bool):
        raise X402FormatError("verifyResponse.isValid must be a boolean")
    for key in ("invalidReason", "invalidMessage", "payer"):
        _optional_string(record, key, "verifyResponse")
    return record  # type: ignore[return-value]


def parse_settle_response(value: Any) -> SettleResponse:
    """Validate a facilitator ``/settle`` response or ``PAYMENT-RESPONSE`` body."""
    record = _object(value, "settleResponse")
    if not isinstance(record.get("success"), bool):
        raise X402FormatError("settleResponse.success must be a boolean")
    _string(record, "transaction", "settleResponse", non_empty=False)
    _string(record, "network", "settleResponse")
    for key in ("payer", "errorReason", "errorMessage"):
        _optional_string(record, key, "settleResponse")
    if record.get("amount") is not None:
        _pattern(record, "amount", "settleResponse", _ATOMIC_AMOUNT_RE)
    return record  # type: ignore[return-value]


def requirements_match(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    """Return whether echoed requirements equal the route's requirements.

    Comparison is exact JSON equality (mppx compares with deep equality),
    except that the ``asset`` and ``payTo`` addresses compare case-insensitively
    because EIP-55 checksums are presentation only.
    """

    def normalized(value: Mapping[str, Any]) -> dict[str, Any]:
        record = dict(value)
        for key in ("asset", "payTo"):
            if isinstance(record.get(key), str):
                record[key] = record[key].lower()
        if record.get("extra") is None:
            record.pop("extra", None)
        return record

    return _json_equal(normalized(actual), normalized(expected))


def _json_equal(left: Any, right: Any) -> bool:
    """JSON equality that never equates booleans with numbers."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return left.keys() == right.keys() and all(_json_equal(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    if isinstance(left, int | float) and isinstance(right, int | float):
        return left == right
    return type(left) is type(right) and left == right
