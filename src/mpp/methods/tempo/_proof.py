"""Tempo zero-amount proof credentials (mppx `tempo/internal/proof.ts`).

A zero-amount charge is paid with an EIP-712 ``Proof(address account,string
challengeId,string realm)`` signature in the ``MPP`` version ``3`` domain instead
of a transaction. The ``account`` field binds the proof to the payer wallet, so a
proof signed for one account cannot be replayed against another.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, NamedTuple

from eth_abi.abi import encode
from eth_hash.auto import keccak

if TYPE_CHECKING:
    from mpp.methods.tempo.account import TempoAccount

DOMAIN_NAME = "MPP"
DOMAIN_VERSION = "3"
PRIMARY_TYPE = "Proof"
# Field order is part of the type hash; it must match mppx's `types`.
TYPES: dict[str, list[dict[str, str]]] = {
    "Proof": [
        {"name": "account", "type": "address"},
        {"name": "challengeId", "type": "string"},
        {"name": "realm", "type": "string"},
    ],
}

_DOMAIN_TYPEHASH = keccak(b"EIP712Domain(string name,string version,uint256 chainId)")
_PROOF_TYPEHASH = keccak(b"Proof(address account,string challengeId,string realm)")
_KEYCHAIN_V1 = 0x03
_KEYCHAIN_V2 = 0x04
_KEYCHAIN_LENGTH = 86


def typed_data(*, account: str, chain_id: int, challenge_id: str, realm: str) -> dict[str, Any]:
    """Return the EIP-712 typed data a proof signs, shaped as mppx's ``typedData``."""
    return {
        "domain": {"name": DOMAIN_NAME, "version": DOMAIN_VERSION, "chainId": chain_id},
        "types": TYPES,
        "primaryType": PRIMARY_TYPE,
        "message": {"account": account, "challengeId": challenge_id, "realm": realm},
    }


def proof_hash(*, account: str, chain_id: int, challenge_id: str, realm: str) -> bytes:
    """Return the 32-byte EIP-712 digest a proof signs."""
    domain = keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256"],
            [
                _DOMAIN_TYPEHASH,
                keccak(DOMAIN_NAME.encode()),
                keccak(DOMAIN_VERSION.encode()),
                chain_id,
            ],
        )
    )
    struct = keccak(
        encode(
            ["bytes32", "address", "bytes32", "bytes32"],
            [_PROOF_TYPEHASH, account, keccak(challenge_id.encode()), keccak(realm.encode())],
        )
    )
    return keccak(b"\x19\x01" + domain + struct)


def proof_source(address: str, chain_id: int) -> str:
    """Return the ``did:pkh`` source a proof credential names its payer with."""
    return f"did:pkh:eip155:{chain_id}:{address}"


def sign_proof(
    signer: TempoAccount,
    *,
    account: str,
    chain_id: int,
    challenge_id: str,
    realm: str,
) -> str:
    """Sign a proof bound to ``account``, returning the signature as 0x-hex.

    When ``signer`` is an access key for ``account`` (a different address), the
    signature is a Keychain V2 envelope (``0x04 || account || inner``), as viem's
    Tempo access-key accounts sign typed data.
    """
    digest = proof_hash(account=account, chain_id=chain_id, challenge_id=challenge_id, realm=realm)
    if signer.address.lower() == account.lower():
        return "0x" + signer.sign_hash(digest).hex()
    # pytempo ships no type information.
    from pytempo import KeychainSignature  # pyright: ignore[reportMissingTypeStubs]

    envelope: Any = KeychainSignature.sign(digest, signer.private_key, account)
    return "0x" + bytes(envelope.to_bytes()).hex()


class ProofSigner(NamedTuple):
    """The address that produced a proof signature."""

    address: str
    keychain: bool
    """Whether the signature was a Keychain envelope (the signer is an access key)."""


def recover_proof_signer(signature: str, *, account: str, digest: bytes) -> ProofSigner | None:
    """Recover the signer of a secp256k1 or Keychain (V1 or V2) proof signature.

    A Keychain envelope must name ``account`` as its user; its inner signature
    signs the digest (V1) or ``keccak256(0x04 || digest || account)`` (V2), as in
    mppx's ``recoverAuthorizedProofSigner``. P256 and WebAuthn signatures are not
    supported. Returns ``None`` for an unrecoverable signature.
    """
    try:
        raw = bytes.fromhex(signature.removeprefix("0x"))
    except ValueError:
        return None
    keychain = len(raw) == _KEYCHAIN_LENGTH and raw[0] in (_KEYCHAIN_V1, _KEYCHAIN_V2)
    if keychain:
        if "0x" + raw[1:21].hex() != account.lower():
            return None
        if raw[0] == _KEYCHAIN_V2:
            digest = keccak(bytes([_KEYCHAIN_V2]) + digest + raw[1:21])
        raw = raw[21:]
    signer = _recover(raw, digest)
    return None if signer is None else ProofSigner(address=signer, keychain=keychain)


def _recover(signature: bytes, digest: bytes) -> str | None:
    """Recover a 65-byte ``r || s || v`` secp256k1 signature (``v`` 0, 1, 27 or 28)."""
    from eth_account import Account

    if len(signature) != 65 or signature[64] not in (0, 1, 27, 28):
        return None
    v = signature[64] if signature[64] >= 27 else signature[64] + 27
    try:
        return Account._recover_hash(  # pyright: ignore[reportPrivateUsage]
            digest, signature=signature[:64] + bytes([v])
        )
    except Exception:
        return None
