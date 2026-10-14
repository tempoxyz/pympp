"""Credential source DID parsing."""

from __future__ import annotations

import re

_PKH_SOURCE_RE = re.compile(r"did:pkh:eip155:(0|[1-9][0-9]*):(0x[a-fA-F0-9]{40})")


def parse_pkh_source(source: str) -> tuple[str, int] | None:
    """Parse a ``did:pkh:eip155:<chainId>:<address>`` DID.

    Returns ``(address, chain_id)`` with the address as written in the DID,
    or ``None`` if malformed.
    """
    match = _PKH_SOURCE_RE.fullmatch(source)
    if match is None:
        return None
    return match.group(2), int(match.group(1))
