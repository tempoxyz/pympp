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

_VERSION = 0x01
_ANONYMOUS = bytes(10)

_TAG: bytes | None = None


def _keccak(data: bytes) -> bytes:
    from eth_hash.auto import keccak

    return keccak(data)


def _get_tag() -> bytes:
    global _TAG
    if _TAG is None:
        _TAG = _keccak(b"mpp")[:4]
    return _TAG


def _fingerprint(value: str) -> bytes:
    return _keccak(value.encode())[:10]


def __getattr__(name: str):  # type: ignore[reportReturnType]
    if name == "TAG":
        return _get_tag()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def encode(server_id: str, client_id: str | None = None) -> str:
    tag = _get_tag()
    buf = bytearray(32)
    buf[0:4] = tag
    buf[4] = _VERSION
    buf[5:15] = _fingerprint(server_id)
    if client_id:
        buf[15:25] = _fingerprint(client_id)
    buf[25:32] = os.urandom(7)
    return "0x" + buf.hex()


def is_mpp_memo(memo: str) -> bool:
    if len(memo) != 66:
        return False
    try:
        memo_tag = bytes.fromhex(memo[2:10])
        memo_version = int(memo[10:12], 16)
    except ValueError:
        return False
    return memo_tag == _get_tag() and memo_version == _VERSION


def verify_server(memo: str, server_id: str) -> bool:
    if not is_mpp_memo(memo):
        return False
    try:
        memo_server = bytes.fromhex(memo[12:32])
    except ValueError:
        return False
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

    try:
        version = int(memo[10:12], 16)
        server_fingerprint = "0x" + memo[12:32]
        client_hex = memo[32:52]
        nonce = "0x" + memo[52:]

        client_fingerprint = None if bytes.fromhex(client_hex) == _ANONYMOUS else "0x" + client_hex
    except ValueError:
        return None

    return DecodedMemo(
        version=version,
        server_fingerprint=server_fingerprint,
        client_fingerprint=client_fingerprint,
        nonce=nonce,
    )
