"""Unit conversion utilities for human-readable amounts.

Converts decimal string amounts to base unit integers, matching the
parseUnits behavior in the TypeScript SDK (viem's parseUnits).

Example:
    >>> parse_units("1.5", 6)
    1500000
    >>> parse_units("0.000025", 6)
    25
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any


def parse_units(value: str, decimals: int) -> int:
    """Convert a human-readable decimal string to base units.

    Args:
        value: Decimal string amount (e.g., "1.5", "0.000025").
        decimals: Number of decimal places for the token.

    Returns:
        Integer amount in base units.

    Raises:
        ValueError: If value is not a valid decimal string, is negative,
            non-finite, or produces fractional base units.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("amount is required")

    try:
        d = Decimal(value.strip())
    except InvalidOperation:
        raise ValueError(f"Invalid amount: {value!r}") from None

    if not d.is_finite():
        raise ValueError("amount must be finite")

    if d < 0:
        raise ValueError("amount must be non-negative")

    result = d * (10**decimals)

    if result != int(result):
        raise ValueError(
            f"Amount {value!r} with {decimals} decimals produces fractional base units"
        )

    return int(result)


def transform_units(request: dict[str, Any]) -> dict[str, Any]:
    """Transform request amounts from human-readable to base units.

    If `decimals` is present in the request, converts `amount` and
    optionally `suggestedDeposit` from human-readable decimal strings
    to base unit strings, then removes the `decimals` key.

    If `decimals` is not present, returns the request unchanged.

    Args:
        request: Payment request parameters.

    Returns:
        Request with amounts converted to base units.
    """
    if "decimals" not in request:
        return request

    result = {**request}
    decimals = result.pop("decimals")

    if not isinstance(decimals, int):
        raise ValueError(f"decimals must be an integer, got {type(decimals).__name__}")

    if "amount" in result:
        result["amount"] = str(parse_units(result["amount"], decimals))

    if "suggestedDeposit" in result and result["suggestedDeposit"] is not None:
        result["suggestedDeposit"] = str(parse_units(result["suggestedDeposit"], decimals))

    return result
