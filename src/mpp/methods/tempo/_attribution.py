"""MPP attribution memo encoding for TIP-20 ``transferWithMemo``.

The SDK generates a challenge-bound attribution memo for every primary
transfer so MPP transactions are identifiable on-chain.

Byte Layout (32 bytes)
~~~~~~~~~~~~~~~~~~~~~~

| Offset | Size | Field                                     |
|--------|------|-------------------------------------------|
| 0..3   | 4    | TAG = keccak256("mpp")[0..3]               |
| 4      | 1    | version (0x01)                            |
| 5..14  | 10   | serverId = keccak256(serverId)[0..9]       |
| 15..24 | 10   | clientId = keccak256(clientId)[0..9] or 0s |
| 25..31 | 7    | nonce = keccak256(challengeId)[0..6]       |

The Tempo charge client uses the Challenge ``realm`` as ``server_id``, so
``verify_server(memo, realm)`` matches on-chain transfers to a server.
"""

from __future__ import annotations

from dataclasses import dataclass

TAG = "0xef1ed712"
"""First 4 bytes of ``keccak256("mpp")``, the on-chain MPP tag."""

ANONYMOUS = "0x" + "00" * 10
"""10 zero bytes used as the client fingerprint of an anonymous client."""

_VERSION = 0x01
_TAG = bytes.fromhex(TAG[2:])
_ANONYMOUS = bytes.fromhex(ANONYMOUS[2:])


def _keccak(data: bytes) -> bytes:
    from eth_hash.auto import keccak

    return keccak(data)


def _fingerprint(value: str) -> bytes:
    return _keccak(value.encode())[:10]


def challenge_nonce(challenge_id: str) -> bytes:
    return _keccak(challenge_id.encode())[:7]


def encode(challenge_id: str, server_id: str, client_id: str | None = None) -> str:
    """Encode a challenge-bound MPP attribution memo.

    Args:
        challenge_id: ID of the Challenge being paid.
        server_id: Server identity, typically the Challenge realm.
        client_id: Optional client identity. Omitted clients are anonymous.

    Returns:
        The 32-byte memo as a ``0x``-prefixed hex string.
    """
    buf = bytearray(32)
    buf[0:4] = _TAG
    buf[4] = _VERSION
    buf[5:15] = _fingerprint(server_id)
    if client_id:
        buf[15:25] = _fingerprint(client_id)
    buf[25:32] = challenge_nonce(challenge_id)
    return "0x" + buf.hex()


def is_mpp_memo(memo: str) -> bool:
    """Return whether ``memo`` carries the MPP tag and a supported version."""
    if len(memo) != 66:
        return False
    try:
        memo_tag = bytes.fromhex(memo[2:10])
        memo_version = int(memo[10:12], 16)
    except ValueError:
        return False
    return memo_tag == _TAG and memo_version == _VERSION


def verify_server(memo: str, server_id: str) -> bool:
    """Return whether ``memo`` is an MPP memo whose server fingerprint matches ``server_id``."""
    if not is_mpp_memo(memo):
        return False
    try:
        memo_server = bytes.fromhex(memo[12:32])
    except ValueError:
        return False
    return memo_server == _fingerprint(server_id)


def verify_challenge_binding(memo: str, challenge_id: str) -> bool:
    """Return whether ``memo`` is an MPP memo whose nonce is bound to ``challenge_id``."""
    if not is_mpp_memo(memo):
        return False
    try:
        memo_nonce = bytes.fromhex(memo[52:66])
    except ValueError:
        return False
    return memo_nonce == challenge_nonce(challenge_id)


@dataclass(frozen=True, slots=True)
class DecodedMemo:
    """Fields of a decoded MPP attribution memo.

    Attributes:
        version: Memo format version.
        server_fingerprint: ``0x``-prefixed ``keccak256(server_id)[0..9]``.
        client_fingerprint: ``0x``-prefixed ``keccak256(client_id)[0..9]``, or
            ``None`` for anonymous clients.
        nonce: ``0x``-prefixed ``keccak256(challenge_id)[0..6]``.
    """

    version: int
    server_fingerprint: str
    client_fingerprint: str | None
    nonce: str


def decode(memo: str) -> DecodedMemo | None:
    """Decode an MPP attribution memo, or return ``None`` if it is not one."""
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
