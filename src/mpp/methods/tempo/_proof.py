"""Tempo zero-amount proof credentials (mppx `tempo/internal/proof.ts`).

A zero-amount charge is paid with an EIP-712 ``Proof(address account,string
challengeId,string realm)`` signature in the ``MPP`` version ``3`` domain instead
of a transaction. The ``account`` field binds the proof to the payer wallet, so a
proof signed for one account cannot be replayed against another.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from eth_abi.abi import encode
from eth_hash.auto import keccak

from mpp._typing import is_dict

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
    """Recover the signer of a secp256k1, P256, WebAuthn or Keychain proof signature.

    A Keychain envelope must name ``account`` as its user; its inner signature (any
    of those primitives) signs the digest (V1) or
    ``keccak256(0x04 || digest || account)`` (V2), as in mppx's
    ``recoverAuthorizedProofSigner``. Returns ``None`` for an unrecoverable
    signature.
    """
    try:
        raw = bytes.fromhex(signature.removeprefix("0x"))
    except ValueError:
        return None
    keychain = len(raw) > 21 and len(raw) != 65 and raw[0] in (_KEYCHAIN_V1, _KEYCHAIN_V2)
    if keychain:
        if "0x" + raw[1:21].hex() != account.lower():
            return None
        if raw[0] == _KEYCHAIN_V2:
            digest = keccak(bytes([_KEYCHAIN_V2]) + digest + raw[1:21])
        raw = raw[21:]
    signer = _recover_primitive(raw, digest)
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


# Tempo primitive signature encodings (tempo-primitives tt_signature.rs).
_P256 = 0x01
_WEBAUTHN = 0x02
_P256_LENGTH = 129  # r || s || pubKeyX || pubKeyY || preHash
_MAX_WEBAUTHN_LENGTH = 2048
_MIN_AUTHENTICATOR_DATA = 37
_FLAG_UP, _FLAG_UV, _FLAG_AT, _FLAG_ED = 0x01, 0x04, 0x40, 0x80
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _recover_primitive(signature: bytes, digest: bytes) -> str | None:
    """Verify a Tempo primitive signature over ``digest`` and return its signer.

    A 65-byte secp256k1 signature recovers its address; a P256 (type ``0x01``)
    or WebAuthn (type ``0x02``) signature carries its public key and returns
    that key's address, as Tempo's ``PrimitiveSignature::recover_signer`` does.
    """
    if len(signature) == 65:
        return _recover(signature, digest)
    if len(signature) < 2:
        return None
    data = signature[1:]
    if signature[0] == _P256:
        if len(data) != _P256_LENGTH:
            return None
        message = hashlib.sha256(digest).digest() if data[128] else digest
        return _verify_p256(message, data[:128])
    if signature[0] == _WEBAUTHN:
        if not 128 <= len(data) <= _MAX_WEBAUTHN_LENGTH:
            return None
        message = _webauthn_message(data[:-128], digest)
        return None if message is None else _verify_p256(message, data[-128:])
    return None


def _verify_p256(message: bytes, data: bytes) -> str | None:
    """Check a low-s P256 signature ``r || s`` over a 32-byte digest by the key
    ``x || y`` and return its address, ``keccak256(x || y)[12:]``."""
    from Crypto.PublicKey import ECC

    r, s = int.from_bytes(data[:32], "big"), int.from_bytes(data[32:64], "big")
    if not (0 < r < _P256_ORDER and 0 < s <= _P256_ORDER // 2):
        return None
    try:
        key = ECC.construct(
            curve="P-256",
            point_x=int.from_bytes(data[64:96], "big"),
            point_y=int.from_bytes(data[96:128], "big"),
        )
    except ValueError:
        return None
    # pycryptodome reads (0, 0) as the point at infinity, which would verify
    # any signature; Tempo rejects it as an invalid key.
    if key.pointQ.is_point_at_infinity():
        return None
    w = pow(s, -1, _P256_ORDER)
    z = int.from_bytes(message, "big") % _P256_ORDER
    generator = ECC.EccPoint(_P256_GX, _P256_GY, "P-256")
    point = generator * (z * w % _P256_ORDER) + key.pointQ * (r * w % _P256_ORDER)
    if point.is_point_at_infinity() or int(point.x) % _P256_ORDER != r:
        return None
    return "0x" + keccak(data[64:128])[12:].hex()


def _webauthn_message(data: bytes, challenge: bytes) -> bytes | None:
    """Validate WebAuthn assertion data and return the digest its key signs.

    As Tempo: user presence or verification set, no attested or extension data
    (so authenticatorData is 37 bytes), clientDataJSON of type ``webauthn.get``
    whose challenge is base64url(challenge); the digest is
    ``sha256(authenticatorData || sha256(clientDataJSON))``.
    """
    import base64
    import json

    if len(data) < _MIN_AUTHENTICATOR_DATA + 32:
        return None
    flags = data[32]
    if not flags & (_FLAG_UP | _FLAG_UV) or flags & (_FLAG_AT | _FLAG_ED):
        return None
    authenticator_data = data[:_MIN_AUTHENTICATOR_DATA]
    client_data_json = data[_MIN_AUTHENTICATOR_DATA:]
    try:
        parsed: object = json.loads(client_data_json)
    except ValueError:
        return None
    if not is_dict(parsed):
        return None
    client_data = cast("dict[str, object]", parsed)
    expected = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()
    if client_data.get("type") != "webauthn.get" or client_data.get("challenge") != expected:
        return None
    return hashlib.sha256(authenticator_data + hashlib.sha256(client_data_json).digest()).digest()
