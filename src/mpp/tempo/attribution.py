"""MPP attribution memos for TIP-20 ``transferWithMemo``.

When no user-provided memo is present, the SDK auto-generates an attribution
memo so MPP transactions are identifiable on-chain.

Byte layout (32 bytes)::

    0..3    TAG = keccak256("mpp")[0..3]
    4       version (0x01)
    5..14   serverId fingerprint = keccak256(serverId)[0..9]
    15..24  clientId fingerprint = keccak256(clientId)[0..9] or zeros
    25..31  nonce = keccak256(challengeId)[0..6]

The Tempo charge client uses the challenge ``realm`` as ``server_id``, so
``verify_server(memo, realm)`` matches on-chain transfers to a server.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from mpp.tempo._internal.hexutil import keccak256

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


TAG: Final = "0x" + keccak256(b"mpp")[:4].hex()
"""First 4 bytes of keccak256("mpp") - the on-chain MPP tag."""

ANONYMOUS: Final = "0x00000000000000000000"
"""10 zero bytes representing an anonymous (no client_id) client."""

_VERSION: Final = 0x01


@dataclass(frozen=True, slots=True, kw_only=True)
class DecodedMemo:
    version: int
    """Memo version (currently always 1)."""
    server_fingerprint: str
    """10-byte server fingerprint hex (keccak256(serverId)[0..9])."""
    client_fingerprint: str | None
    """10-byte client fingerprint hex, or ``None`` if anonymous."""
    nonce: str
    """7-byte challenge-bound nonce hex (keccak256(challengeId)[0..6])."""


def _fingerprint(value: str) -> bytes:
    return keccak256(value.encode())[:10]


def _challenge_nonce(challenge_id: str) -> bytes:
    return keccak256(challenge_id.encode())[:7]


def encode(*, challenge_id: str, server_id: str, client_id: str | None = None) -> str:
    """Encodes an MPP attribution memo as a ``bytes32`` hex string."""
    memo = bytearray(32)
    memo[0:4] = bytes.fromhex(TAG[2:])
    memo[4] = _VERSION
    memo[5:15] = _fingerprint(server_id)
    if client_id:
        memo[15:25] = _fingerprint(client_id)
    # Binds the memo to the challenge, preventing transaction-hash stealing.
    memo[25:32] = _challenge_nonce(challenge_id)
    return "0x" + memo.hex()


def is_mpp_memo(memo: str) -> bool:
    """Whether a ``bytes32`` memo starts with the MPP tag and version byte."""
    if len(memo) != 66:
        return False
    try:
        version = int(memo[10:12], 16)
    except ValueError:
        return False
    return memo[:10].lower() == TAG.lower() and version == _VERSION


def verify_server(memo: str, server_id: str) -> bool:
    """Whether a memo's server fingerprint matches ``server_id``."""
    if not is_mpp_memo(memo):
        return False
    return memo[12:32].lower() == _fingerprint(server_id).hex()


def decode(memo: str) -> DecodedMemo | None:
    """Decodes an MPP attribution memo, or returns ``None`` for non-MPP memos."""
    if not is_mpp_memo(memo):
        return None
    client_hex = "0x" + memo[32:52]
    return DecodedMemo(
        version=int(memo[10:12], 16),
        server_fingerprint="0x" + memo[12:32],
        client_fingerprint=None if client_hex.lower() == ANONYMOUS else client_hex,
        nonce="0x" + memo[52:],
    )


def verify_challenge_binding(memo: str, challenge_id: str) -> bool:
    """Whether a memo's nonce is bound to ``challenge_id``."""
    decoded = decode(memo)
    if decoded is None:
        return False
    return decoded.nonce.lower() == "0x" + _challenge_nonce(challenge_id).hex()
