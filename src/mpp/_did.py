"""Credential source DID parsing."""

from __future__ import annotations

import re
from typing import NamedTuple

# Chain IDs are bounded like JavaScript safe integers, matching mppx.
_MAX_CHAIN_ID = 2**53 - 1
_PKH_SOURCE_RE = re.compile(r"did:pkh:eip155:(0|[1-9][0-9]{0,15}):(0x[a-fA-F0-9]{40})")


class PkhSource(NamedTuple):
    """A parsed ``did:pkh:eip155:<chainId>:<address>`` DID."""

    address: str
    """The address as written in the DID."""
    chain_id: int


def parse_pkh_source(source: str) -> PkhSource | None:
    """Parse a ``did:pkh:eip155:<chainId>:<address>`` credential source.

    Parsing does not authenticate the address: a credential's ``source`` is
    asserted by the client. Use the payer verified by the payment method
    (``Validation.payer`` / ``Receipt.payer``) to identify who paid.

    Returns:
        The address and chain ID, or ``None`` if ``source`` is malformed or
        its chain ID exceeds ``2**53 - 1``.
    """
    match = _PKH_SOURCE_RE.fullmatch(source)
    if match is None:
        return None
    chain_id = int(match.group(1))
    if chain_id > _MAX_CHAIN_ID:
        return None
    return PkhSource(address=match.group(2), chain_id=chain_id)
