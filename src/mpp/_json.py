"""JSON helpers with JavaScript-compatible output.

``dumps`` matches ``JSON.stringify`` (compact, ECMAScript property order: integer-index keys
ascending, then insertion order; ECMAScript number formatting)
and ``canonicalize`` matches RFC 8785 / ``ox`` ``Json.canonicalize`` (keys sorted by UTF-16 code
units). Both are used for wire values whose bytes must agree with mppx.
"""

import json
import math
from collections.abc import Mapping
from decimal import Decimal
from typing import Any

from pydantic import BaseModel


def to_json_value(value: Any) -> Any:
    """Converts pydantic models (recursively) into plain JSON-compatible values."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): to_json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [to_json_value(item) for item in value]
    return value


def dumps(value: Any) -> str:
    """Serializes ``value`` exactly like JavaScript ``JSON.stringify`` (no whitespace)."""
    return _encode(to_json_value(value), canonical=False)


def canonicalize(value: Any) -> str:
    """Serializes ``value`` as RFC 8785 canonical JSON (JCS)."""
    return _encode(to_json_value(value), canonical=True)


def loads(text: str | bytes) -> Any:
    """Parses JSON text."""
    return json.loads(text)


_MAX_ARRAY_INDEX = 2**32 - 2


def _array_index(key: str) -> int | None:
    """Returns ``key`` as a JavaScript array index (``"0"`` … ``"4294967294"``), else ``None``."""
    if not key.isascii() or not key.isdigit() or (len(key) > 1 and key[0] == "0") or len(key) > 10:
        return None
    index = int(key)
    return index if index <= _MAX_ARRAY_INDEX else None


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _encode(value: Any, *, canonical: bool) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return format_number(value)
    if isinstance(value, Mapping):
        items = list(value.items())
        if canonical:
            items.sort(key=lambda item: _utf16_key(str(item[0])))
        else:
            # JavaScript enumerates integer-index keys first, in ascending numeric order.
            indices = sorted(
                (item for item in items if _array_index(str(item[0])) is not None),
                key=lambda item: _array_index(str(item[0])) or 0,
            )
            if indices:
                items = indices + [item for item in items if _array_index(str(item[0])) is None]
        body = ",".join(
            f"{json.dumps(str(key), ensure_ascii=False)}:{_encode(item, canonical=canonical)}"
            for key, item in items
        )
        return "{" + body + "}"
    if isinstance(value, list | tuple):
        return "[" + ",".join(_encode(item, canonical=canonical) for item in value) + "]"
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def format_number(value: float) -> str:
    """Formats a float like ECMAScript ``Number.prototype.toString``."""
    if not math.isfinite(value):
        raise ValueError("Cannot serialize non-finite number")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    decimal = Decimal(repr(abs(value)))
    _, digit_tuple, exponent = decimal.as_tuple()
    assert isinstance(exponent, int)
    digits = "".join(map(str, digit_tuple)).rstrip("0") or "0"
    trailing = len("".join(map(str, digit_tuple))) - len(digits)
    exponent += trailing
    k = len(digits)
    n = exponent + k
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = f"{digits[:n]}.{digits[n:]}"
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits[0] + (f".{digits[1:]}" if k > 1 else "")
        text = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + text
