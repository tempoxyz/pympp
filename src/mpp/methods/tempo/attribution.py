"""MPP attribution memos for identifying Tempo payments on-chain.

The Tempo client writes a 32-byte, challenge-bound attribution memo on every
primary ``transferWithMemo`` transfer. Use these helpers to recognize MPP
transfers and reconcile them with the server and Challenge they paid. The
client uses the Challenge ``realm`` as ``server_id``. Encoding and verification
require the ``tempo`` extra.

Example:
    from mpp.methods.tempo import attribution

    if attribution.verify_server(memo, "api.example.com"):
        decoded = attribution.decode(memo)
"""

from mpp.methods.tempo._attribution import (
    ANONYMOUS,
    TAG,
    DecodedMemo,
    decode,
    encode,
    is_mpp_memo,
    verify_challenge_binding,
    verify_server,
)

__all__ = [
    "ANONYMOUS",
    "TAG",
    "DecodedMemo",
    "decode",
    "encode",
    "is_mpp_memo",
    "verify_challenge_binding",
    "verify_server",
]
