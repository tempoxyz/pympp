"""Decimal string to integer base-unit conversion."""

import re

_DECIMAL = re.compile(r"-?(?:\d+(?:\.\d*)?|\.\d+)", re.ASCII)


def parse_units(value: str, decimals: int) -> int:
    """Converts a decimal string to its integer representation at ``decimals`` precision.

    Fractional digits beyond the precision are rounded half away from zero (viem ``parseUnits``).

    Raises:
        ValueError: When ``decimals`` is not a non-negative integer or ``value`` is not a
            decimal number.
    """
    if isinstance(decimals, bool) or not isinstance(decimals, int) or decimals < 0:
        raise ValueError("Decimals must be a non-negative integer.")
    if not _DECIMAL.fullmatch(value):
        raise ValueError(f"Value `{value}` is not a valid decimal number.")
    negative = value.startswith("-")
    integer, _, fraction = value.removeprefix("-").partition(".")
    kept = fraction[:decimals].ljust(decimals, "0")
    result = int(f"{integer or '0'}{kept}")
    if len(fraction) > decimals and fraction[decimals] >= "5":
        result += 1
    return -result if negative else result
