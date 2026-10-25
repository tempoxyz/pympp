"""Decimal amount <-> base unit conversion (viem ``parseUnits`` / ``formatUnits``)."""

from __future__ import annotations

import re

_DECIMAL_RE = re.compile(r"^-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z")


def parse_units(value: str, decimals: int) -> int:
    """Parses a decimal string into base units, rounding half away from zero."""
    if isinstance(decimals, bool) or not isinstance(decimals, int) or decimals < 0:
        raise ValueError(f"`decimals` must be a non-negative integer. Got `{decimals}`.")
    if not _DECIMAL_RE.fullmatch(value):
        raise ValueError(f"Value `{value}` is not a valid decimal number.")
    integer, _, fraction = value.partition(".")
    negative = integer.startswith("-")
    integer = integer.removeprefix("-") or "0"
    fraction = fraction.rstrip("0")
    if decimals == 0:
        units = int(integer) + (1 if fraction and int(fraction[0]) >= 5 else 0)
    elif len(fraction) > decimals:
        units = int(integer + fraction[:decimals]) + (1 if int(fraction[decimals]) >= 5 else 0)
    else:
        units = int(integer + fraction.ljust(decimals, "0"))
    return -units if negative else units


def format_units(value: int, decimals: int) -> str:
    """Formats base units as a decimal string without trailing zeros."""
    negative = value < 0
    digits = str(abs(value)).rjust(decimals + 1, "0")
    integer, fraction = digits[: len(digits) - decimals], digits[len(digits) - decimals :]
    fraction = fraction.rstrip("0")
    return f"{'-' if negative else ''}{integer}{'.' + fraction if fraction else ''}"
