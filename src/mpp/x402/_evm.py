"""Small EVM helpers shared by :mod:`mpp.x402` and :mod:`mpp.evm` (viem equivalents).

``eth-utils`` (``evm`` extra) is imported lazily so importing :mod:`mpp.x402` stays cheap.
"""

import re

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}\Z")
_DECIMAL = re.compile(r"^-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z")


def is_address(value: object) -> bool:
    """Returns whether ``value`` is a ``0x`` hex address (viem ``isAddress`` non-strict)."""
    return isinstance(value, str) and _ADDRESS.match(value) is not None


def get_address(address: str) -> str:
    """Returns the EIP-55 checksummed address (viem ``getAddress``).

    Raises:
        ValueError: When ``address`` is not a hex address.
    """
    if not is_address(address):
        raise ValueError(f'Address "{address}" is invalid.')
    from eth_utils.address import to_checksum_address

    return to_checksum_address(address)


def is_address_equal(left: str, right: str) -> bool:
    """Case-insensitive address comparison (raises on malformed addresses)."""
    return get_address(left) == get_address(right)


def parse_units(value: str, decimals: int) -> int:
    """Parses a decimal string into base units, rounding half away from zero (viem)."""
    if not _DECIMAL.match(value):
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
    """Formats base units as a decimal string without trailing zeros (viem)."""
    negative = value < 0
    digits = str(abs(value)).rjust(decimals + 1, "0")
    integer, fraction = digits[: len(digits) - decimals], digits[len(digits) - decimals :]
    fraction = fraction.rstrip("0")
    return f"{'-' if negative else ''}{integer}{'.' + fraction if fraction else ''}"
