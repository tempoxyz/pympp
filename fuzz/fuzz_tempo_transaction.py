"""Fuzz the 0x76 transaction and 0x78 fee-payer envelope decoders.

Inputs are raw transaction bytes. The decoders must only fail as documented:
``decode_fee_payer_envelope`` raises ValueError, ``_transaction_fee_token``
raises RuntimeError, and the other helpers return None or their input instead
of raising.
"""

from __future__ import annotations

import atheris
from _harness import fuzz

with atheris.instrument_imports(include=["mpp", "rlp"]):
    from mpp.methods.tempo.fee_payer_envelope import decode_fee_payer_envelope
    from mpp.methods.tempo.intents import (
        _canonical_raw_transaction,
        _transaction_fee_token,
        _transaction_sender,
        _transaction_valid_before,
    )


def test_one_input(data: bytes) -> None:
    raw = "0x" + data.hex()
    try:
        decode_fee_payer_envelope(data)
    except ValueError:
        pass
    try:
        _transaction_fee_token(raw)
    except RuntimeError:
        pass
    _transaction_sender(raw)
    _transaction_valid_before(raw)
    canonical = _canonical_raw_transaction(raw)
    # Canonicalizing is idempotent.
    assert _canonical_raw_transaction(canonical) == canonical


if __name__ == "__main__":
    fuzz(test_one_input, allowed=())
