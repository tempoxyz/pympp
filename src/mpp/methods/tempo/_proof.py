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

import math
import time
from typing import TYPE_CHECKING, Any, cast

from eth_abi.abi import decode, encode
from eth_hash.auto import keccak

from mpp.methods.tempo.session._proof import proof_digest
from mpp.methods.tempo.session._voucher import (
    _recover_canonical,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from mpp.store import Store

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


PROOF_CLAIM_PREFIX = "mppx:charge:proof:"
"""Store key prefix claiming a used proof's challenge ID, shared with mppx and session bootstrap."""

_REPLAY_MARKER_TYPE = "mppx:replay"


def proof_claim_key(challenge_id: str) -> str:
    """The store key claiming a proof's challenge (mppx ``getProofStoreKey``)."""
    return PROOF_CLAIM_PREFIX + challenge_id


def _is_live_claim(value: Any, now: float) -> bool:
    """Whether a stored claim still holds: anything but an expired replay marker (as mppx)."""
    if value is None:
        return False
    if not isinstance(value, dict):
        return True
    marker = cast("dict[str, Any]", value)
    if marker.get("type") != _REPLAY_MARKER_TYPE:
        return True
    expires = marker.get("expires")
    return not isinstance(expires, int | float) or expires > now * 1000


async def claim_proof(store: Store, challenge_id: str, expires_at: float) -> bool:
    """Record a proof's first use until ``expires_at`` (mppx ``Store.tryClaim``).

    Returns ``False`` when the proof was already claimed or its challenge has
    expired. Stores with ``put_if_absent_until`` claim until the challenge expires;
    compare-and-set stores write mppx's expiring replay marker, which a later claim
    may replace once it has expired. Other stores only offer ``put_if_absent``, so
    their claim (the same marker) is never released: still single-use, but kept.
    """
    from mpp.store import CompareAndSetStore, ExpiringStore

    if not math.isfinite(expires_at) or expires_at <= time.time():
        return False
    key = proof_claim_key(challenge_id)
    marker = {"expires": math.floor(expires_at * 1000), "type": _REPLAY_MARKER_TYPE}
    if isinstance(store, ExpiringStore):
        return await store.put_if_absent_until(key, marker, expires_at)
    if isinstance(store, CompareAndSetStore):
        current = await store.get(key)
        if _is_live_claim(current, time.time()):
            return False
        return await store.compare_and_set(key, current, marker)
    return await store.put_if_absent(key, marker)


async def is_proof_claimed(store: Store, challenge_id: str) -> bool:
    """Whether a proof's challenge is already claimed (see :func:`claim_proof`)."""
    return _is_live_claim(await store.get(proof_claim_key(challenge_id)), time.time())
