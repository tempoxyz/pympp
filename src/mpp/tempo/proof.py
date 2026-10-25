"""Zero-amount Tempo proof credentials (EIP-712 domain ``MPP`` version ``3``).

A proof binds a payer wallet (``account``) to a challenge ``id`` and
``realm``. Clients sign :func:`typed_data`; servers rebuild it from the
credential ``source`` DID (:func:`parse_proof_source`) and verify.
"""

from __future__ import annotations

from mpp.tempo._internal.proof import (
    PRIMARY_TYPE,
    TYPES,
    PkhSource,
    domain,
    hash,
    message,
    parse_pkh_source,
    proof_source,
    typed_data,
)

parse_proof_source = parse_pkh_source
"""Parses a proof credential source DID (alias of :func:`parse_pkh_source`)."""

__all__ = [
    "PRIMARY_TYPE",
    "TYPES",
    "PkhSource",
    "domain",
    "hash",
    "message",
    "parse_pkh_source",
    "parse_proof_source",
    "proof_source",
    "typed_data",
]
