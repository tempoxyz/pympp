"""MPP attribution memo encoding for TIP-20 ``transferWithMemo``.

When no user-provided memo is present, the SDK auto-generates an
attribution memo so MPP transactions are identifiable on-chain.

Byte Layout (32 bytes)
~~~~~~~~~~~~~~~~~~~~~~

| Offset | Size | Field                                     |
|--------|------|-------------------------------------------|
| 0..3   | 4    | TAG = keccak256("mpp")[0..3]               |
| 4      | 1    | version (0x01)                            |
| 5..14  | 10   | serverId = keccak256(serverId)[0..9]       |
| 15..24 | 10   | clientId = keccak256(clientId)[0..9] or 0s |
| 25..31 | 7    | nonce (random bytes)                      |
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from eth_hash.auto import keccak

TAG: bytes = keccak(b"mpp")[:4]

_VERSION = 0x01
_ANONYMOUS = bytes(10)


def _fingerprint(value: str) -> bytes:
    return keccak(value.encode())[:10]


def encode(server_id: str, client_id: str | None = None) -> str:
    buf = bytearray(32)
    buf[0:4] = TAG
    buf[4] = _VERSION
    buf[5:15] = _fingerprint(server_id)
    if client_id:
        buf[15:25] = _fingerprint(client_id)
    buf[25:32] = os.urandom(7)
    return "0x" + buf.hex()


def is_mpp_memo(memo: str) -> bool:
    if len(memo) != 66:
        return False
    memo_tag = bytes.fromhex(memo[2:10])
    memo_version = int(memo[10:12], 16)
    return memo_tag == TAG and memo_version == _VERSION


def verify_server(memo: str, server_id: str) -> bool:
    if not is_mpp_memo(memo):
        return False
    memo_server = bytes.fromhex(memo[12:32])
    return memo_server == _fingerprint(server_id)


@dataclass(frozen=True, slots=True)
class DecodedMemo:
    version: int
    server_fingerprint: str
    client_fingerprint: str | None
    nonce: str


def decode(memo: str) -> DecodedMemo | None:
    if not is_mpp_memo(memo):
        return None

    version = int(memo[10:12], 16)
    server_fingerprint = "0x" + memo[12:32]
    client_hex = memo[32:52]
    nonce = "0x" + memo[52:]

    client_fingerprint = None if bytes.fromhex(client_hex) == _ANONYMOUS else "0x" + client_hex

    return DecodedMemo(
        version=version,
        server_fingerprint=server_fingerprint,
        client_fingerprint=client_fingerprint,
        nonce=nonce,
    )
