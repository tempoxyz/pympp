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

    # A negative scale divides the amount instead of scaling it, and only
    # reports the loss when the division leaves a remainder: "100" with -2
    # decimals returns 1 while "7" with -1 raises. Reject it outright, as
    # mpp-go does.
    if decimals < 0:
        raise ValueError(f"decimals must be non-negative, got {decimals}")

    # Scale with integer arithmetic. ``d * (10**decimals)`` is evaluated in the
    # active decimal context, whose default precision is 28 significant digits,
    # so amounts longer than that would be rounded into a different — and still
    # integral — value and returned as a silently wrong base-unit amount.
    _sign, digits, exponent = d.as_tuple()
    unscaled = int("".join(str(digit) for digit in digits))
    scale = int(exponent) + decimals

    if unscaled == 0:
        return 0

    if scale >= 0:
        return unscaled * 10**scale

    # ``unscaled`` has exactly ``len(digits)`` digits, so a divisor carrying at
    # least that many zeros cannot divide it. Testing the exponent before
    # building the divisor short-circuits values such as ``"1e-10000000"``,
    # which would otherwise materialize a ten-million-digit integer only to be
    # rejected.
    divisor_zeros = -scale
    if divisor_zeros >= len(digits) or unscaled % 10**divisor_zeros:
        raise ValueError(
            f"Amount {value!r} with {decimals} decimals produces fractional base units"
        )

    return unscaled // 10**divisor_zeros


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

    # ``bool`` is a subclass of ``int``, so an unintended ``"decimals": true``
    # would otherwise be accepted as 1 and quietly rescale the amount.
    if isinstance(decimals, bool) or not isinstance(decimals, int):
        raise ValueError(f"decimals must be an integer, got {type(decimals).__name__}")

    if "amount" in result:
        result["amount"] = str(parse_units(result["amount"], decimals))

    if "suggestedDeposit" in result and result["suggestedDeposit"] is not None:
        result["suggestedDeposit"] = str(parse_units(result["suggestedDeposit"], decimals))

    return result
