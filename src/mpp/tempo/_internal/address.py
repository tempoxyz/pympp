"""Address helpers, including Tempo-formatted (``tempox…``) addresses."""

from __future__ import annotations

import re

from eth_utils.address import to_checksum_address

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}\Z")
_TEMPO_PREFIX = "tempox"


class InvalidTempoAddressError(ValueError):
    pass


def is_address(value: object, *, strict: bool = True) -> bool:
    """Returns whether ``value`` is a hex address.

    With ``strict`` (viem's default), mixed-case addresses must carry a valid
    EIP-55 checksum.
    """
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        return False
    if not strict:
        return True
    body = value[2:]
    if body == body.lower() or body == body.upper():
        return True
    return to_checksum_address(value) == value


def checksum(address: str) -> str:
    """Returns the EIP-55 checksummed form of a hex address."""
    if not _ADDRESS_RE.fullmatch(address):
        raise ValueError(f"Address {address!r} is invalid.")
    return to_checksum_address(address)


def parse_tempo(address: str) -> str:
    """Parses a ``tempox…`` address into its checksummed hex address."""
    if not address.startswith(_TEMPO_PREFIX):
        raise InvalidTempoAddressError(
            f'Tempo address "{address}" has an invalid prefix. Expected "tempox".'
        )
    hex_address = address[len(_TEMPO_PREFIX) :]
    if not _ADDRESS_RE.fullmatch(hex_address):
        raise InvalidTempoAddressError(f'Tempo address "{address}" is invalid.')
    return to_checksum_address(hex_address)


def is_tempo_address(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parse_tempo(value)
    except InvalidTempoAddressError:
        return False
    return True


def format_tempo(address: str) -> str:
    """Formats a hex or Tempo address as ``tempox<lowercase hex>``."""
    return _TEMPO_PREFIX + resolve(address).lower()


def resolve(address: str) -> str:
    """Resolves a hex or Tempo-formatted address to a hex address."""
    if address.startswith("tempo"):
        return parse_tempo(address)
    return address


def is_equal(a: str, b: str) -> bool:
    """Whether two hex or Tempo-formatted addresses resolve to the same address."""
    return resolve(a).lower() == resolve(b).lower()
