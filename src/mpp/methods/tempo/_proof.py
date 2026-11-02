"""Server-side verification of Tempo zero-amount proof credentials.

Mirrors mppx ``tempo/server/Charge.ts``: a proof is an EIP-712 ``Proof`` signature
(domain ``MPP`` version 3) binding the source account to the challenge ID and realm.
It is valid when the source account signed it itself, or when an access key the
AccountKeychain holds for the source, unrevoked and unexpired, signed it: bare, or
wrapped in a Keychain V1 (``0x03``) or V2 (``0x04``) envelope naming the source.

Only primitive secp256k1 signatures are recovered (bare or inside a keychain
envelope); P256, WebAuthn and smart-account (ERC-1271) proofs are not supported yet.
"""

from __future__ import annotations

import time
from typing import Any

from eth_abi.abi import decode, encode
from eth_hash.auto import keccak

from mpp.methods.tempo.session._proof import proof_digest
from mpp.methods.tempo.session._voucher import (
    _recover_canonical,  # pyright: ignore[reportPrivateUsage]
)

ACCOUNT_KEYCHAIN_ADDRESS = "0xaAAAaaAA00000000000000000000000000000000"
"""The AccountKeychain precompile."""

_GET_KEY_SELECTOR = "bc298553"  # getKey(address,address)
_KEYCHAIN_V1 = 0x03
_KEYCHAIN_V2 = 0x04
_SECP256K1_LENGTH = 65
_KEYCHAIN_LENGTH = 1 + 20 + _SECP256K1_LENGTH


def recover_authorized_proof_signer(
    signature: str, *, source: str, chain_id: int, challenge_id: str, realm: str
) -> str | None:
    """Recover the key that signed a proof for ``source`` (mppx ``recoverAuthorizedProofSigner``).

    Returns the signer of a bare secp256k1 signature over the proof digest, or the
    inner signer of a keychain envelope naming ``source`` (V1 signs the proof
    digest, V2 signs ``keccak256(0x04 || digest || source)``). Returns ``None``
    for anything else. The caller still checks that the signer is ``source`` or
    one of its active access keys.
    """
    try:
        raw = bytes.fromhex(signature.removeprefix("0x"))
        digest = proof_digest(
            account=source, chain_id=chain_id, challenge_id=challenge_id, realm=realm
        )
    except Exception:
        return None
    if not signature.startswith("0x"):
        return None
    if len(raw) == _SECP256K1_LENGTH:
        return _recover_canonical(signature, digest)
    if len(raw) != _KEYCHAIN_LENGTH or raw[0] not in (_KEYCHAIN_V1, _KEYCHAIN_V2):
        return None
    user_address = raw[1:21]
    if user_address != bytes.fromhex(source.removeprefix("0x")):
        return None
    digest_bytes = bytes.fromhex(digest.removeprefix("0x"))
    payload = (
        keccak(bytes([_KEYCHAIN_V2]) + digest_bytes + user_address)
        if raw[0] == _KEYCHAIN_V2
        else digest_bytes
    )
    return _recover_canonical("0x" + raw[21:].hex(), "0x" + payload.hex())


def get_key_call_data(account: str, access_key: str) -> str:
    """ABI-encoded ``AccountKeychain.getKey(account, accessKey)`` call data."""
    return "0x" + _GET_KEY_SELECTOR + encode(["address", "address"], [account, access_key]).hex()


def is_active_key_info(result: Any, access_key: str, now: int | None = None) -> bool:
    """Whether a ``getKey`` result describes ``access_key``, unrevoked and unexpired.

    The result is ``(uint8 signatureType, address keyId, uint64 expiry,
    bool enforceLimits, bool isRevoked)``; an unknown key reads as zeros.
    """
    try:
        _, key_id, expiry, _, revoked = decode(
            ["uint8", "address", "uint64", "bool", "bool"],
            bytes.fromhex(str(result).removeprefix("0x")),
        )
    except Exception:
        return False
    if str(key_id).lower() != access_key.lower():
        return False
    current = int(time.time()) if now is None else now
    return not revoked and int(expiry) > current
