"""Tempo signature envelopes on top of pytempo.

secp256k1 signatures are pytempo :class:`~pytempo.Signature` (``r || s || v``, ``v`` is 27/28)
and keychain v2 signatures over a secp256k1 inner signature are pytempo
:class:`~pytempo.KeychainSignature`. This module adds what pytempo lacks (ox
``SignatureEnvelope``): parsing serialized envelopes, P256 and WebAuthn signatures, keychain v1
(or non-secp256k1 inner) envelopes, native multisig envelopes, verification and RPC formatting.

- P256: ``0x01 || r || s || x || y || prehash``
- WebAuthn: ``0x02 || authenticatorData || clientDataJSON || r || s || x || y``
- keychain: ``0x03`` (v1) / ``0x04`` (v2) ``|| userAddress || inner``
- multisig: ``0x05 || rlp([account, [salt, version, threshold, [[owner, weight], ...]],
  [ownerSignature, ...]])`` (TIP-1061, ox ``MultisigConfig``)
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Final, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)
from eth_keys.datatypes import Signature as _EthKeysSignature
from eth_keys.exceptions import BadSignature
from eth_utils.exceptions import ValidationError
from pytempo import KeychainSignature, Signature

from mpp.tempo._internal.address import checksum, is_address, is_equal, resolve
from mpp.tempo._internal.hexutil import (
    keccak256,
    rlp_decode,
    rlp_encode,
    to_bytes,
    to_hex,
    uint_to_bytes,
)

type KeyType = Literal["secp256k1", "p256", "webAuthn"]
type KeychainVersion = Literal["v1", "v2"]

MAGIC_BYTES: Final = b"\x77" * 32
"""Suffix that marks a serialized envelope inside an ERC-1271 style payload."""

P256_N: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

_P256_TYPE: Final = 0x01
_WEBAUTHN_TYPE: Final = 0x02
_KEYCHAIN_V1_TYPE: Final = 0x03
_KEYCHAIN_V2_TYPE: Final = 0x04
_MULTISIG_TYPE: Final = 0x05


class InvalidSignatureEnvelopeError(ValueError):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class P256Signature:
    r: int
    s: int
    public_key_x: int
    public_key_y: int
    prehash: bool

    @property
    def type(self) -> Literal["p256"]:
        return "p256"

    def to_bytes(self) -> bytes:
        return (
            bytes([_P256_TYPE])
            + _u256(self.r)
            + _u256(self.s)
            + _u256(self.public_key_x)
            + _u256(self.public_key_y)
            + bytes([1 if self.prehash else 0])
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class WebAuthnSignature:
    r: int
    s: int
    public_key_x: int
    public_key_y: int
    authenticator_data: str
    """Hex-encoded authenticator data."""
    client_data_json: str

    @property
    def type(self) -> Literal["webAuthn"]:
        return "webAuthn"

    def to_bytes(self) -> bytes:
        return (
            bytes([_WEBAUTHN_TYPE])
            + to_bytes(self.authenticator_data)
            + self.client_data_json.encode()
            + _u256(self.r)
            + _u256(self.s)
            + _u256(self.public_key_x)
            + _u256(self.public_key_y)
        )


type PrimitiveSignature = Signature | P256Signature | WebAuthnSignature


@dataclass(frozen=True, slots=True, kw_only=True)
class KeychainEnvelope:
    """An access-key signature pytempo's :class:`~pytempo.KeychainSignature` cannot hold.

    That is a keychain v1 envelope, or a v2 envelope around a P256 or WebAuthn signature.
    """

    user_address: str
    inner: PrimitiveSignature
    version: KeychainVersion = "v2"

    @property
    def type(self) -> Literal["keychain"]:
        return "keychain"

    def to_bytes(self) -> bytes:
        type_id = _KEYCHAIN_V1_TYPE if self.version == "v1" else _KEYCHAIN_V2_TYPE
        return bytes([type_id]) + to_bytes(self.user_address) + self.inner.to_bytes()


@dataclass(frozen=True, slots=True, kw_only=True)
class MultisigOwner:
    owner: str
    weight: int


@dataclass(frozen=True, slots=True, kw_only=True)
class MultisigConfig:
    """A native multisig (TIP-1061) configuration (ox ``MultisigConfig.Config``)."""

    owners: tuple[MultisigOwner, ...]
    threshold: int
    salt: str = "0x" + "00" * 32
    version: int = 0


@dataclass(frozen=True, slots=True, kw_only=True)
class MultisigSignature:
    """A native multisig signature: the full current config plus primitive owner approvals."""

    account: str
    config: MultisigConfig
    signatures: tuple[PrimitiveSignature, ...]

    @property
    def type(self) -> Literal["multisig"]:
        return "multisig"

    def to_bytes(self) -> bytes:
        assert_multisig(self)
        return bytes([_MULTISIG_TYPE]) + _multisig_rlp(self)


type AnyKeychainSignature = KeychainSignature | KeychainEnvelope
type SignatureEnvelope = PrimitiveSignature | AnyKeychainSignature | MultisigSignature


def secp256k1_signature(*, r: int, s: int, y_parity: int) -> Signature:
    """A pytempo signature with ox's ``v`` encoding (27/28)."""
    try:
        return Signature(r=r, s=s, v=27 + y_parity)
    except ValueError as error:
        raise InvalidSignatureEnvelopeError(str(error)) from error


def y_parity(signature: Signature) -> int:
    return signature.v if signature.v in (0, 1) else signature.v - 27


def v_to_y_parity(v: int) -> int:
    if v in (0, 27):
        return 0
    if v in (1, 28):
        return 1
    if v >= 35:
        return 1 if v % 2 == 0 else 0
    raise InvalidSignatureEnvelopeError(f"Invalid v value {v}.")


def parse_secp256k1(signature: str | bytes) -> Signature:
    """Parses a 65-byte ``r || s || v`` signature."""
    raw = to_bytes(signature)
    if len(raw) != 65:
        raise InvalidSignatureEnvelopeError(f"Expected a 65-byte signature, got {len(raw)} bytes.")
    return secp256k1_signature(
        r=int.from_bytes(raw[:32], "big"),
        s=int.from_bytes(raw[32:64], "big"),
        y_parity=v_to_y_parity(raw[64]),
    )


def keychain_sign_payload(payload: bytes, user_address: str) -> bytes:
    """Keychain v2 inner payload: ``keccak256(0x04 || payload || userAddress)``."""
    return keccak256(bytes([_KEYCHAIN_V2_TYPE]) + payload + to_bytes(resolve(user_address)))


def keychain_signature(
    *, user_address: str, inner: PrimitiveSignature, version: KeychainVersion = "v2"
) -> AnyKeychainSignature:
    """A keychain envelope: pytempo's for v2 over secp256k1, :class:`KeychainEnvelope` otherwise."""
    if version == "v2" and isinstance(inner, Signature):
        return KeychainSignature(root_account=resolve(user_address), inner=inner)
    return KeychainEnvelope(user_address=user_address, inner=inner, version=version)


def keychain_parts(
    envelope: AnyKeychainSignature,
) -> tuple[str, PrimitiveSignature, KeychainVersion]:
    """``(user_address, inner, version)`` of either keychain representation."""
    if isinstance(envelope, KeychainSignature):
        return to_hex(bytes(envelope.root_account)), envelope.inner, "v2"
    return envelope.user_address, envelope.inner, envelope.version


def serialize(envelope: SignatureEnvelope, *, magic: bool = False) -> str:
    """Serializes a signature envelope to hex."""
    return to_hex(envelope.to_bytes() + (MAGIC_BYTES if magic else b""))


def deserialize(value: str | bytes) -> SignatureEnvelope:
    """Parses a serialized signature envelope (an optional magic suffix is stripped)."""
    raw = to_bytes(value)
    if raw.endswith(MAGIC_BYTES):
        raw = raw[: -len(MAGIC_BYTES)]
    if len(raw) == 65:
        return parse_secp256k1(raw)
    if not raw:
        raise InvalidSignatureEnvelopeError(
            "Unable to deserialize signature envelope: empty value."
        )
    type_id, data = raw[0], raw[1:]
    if type_id == _P256_TYPE:
        if len(data) != 129:
            raise InvalidSignatureEnvelopeError(
                "Unable to deserialize signature envelope: Invalid P256 signature envelope size: "
                f"expected 129 bytes, got {len(data)} bytes"
            )
        return P256Signature(
            r=int.from_bytes(data[0:32], "big"),
            s=int.from_bytes(data[32:64], "big"),
            public_key_x=int.from_bytes(data[64:96], "big"),
            public_key_y=int.from_bytes(data[96:128], "big"),
            prehash=data[128] != 0,
        )
    if type_id == _WEBAUTHN_TYPE:
        if len(data) < 128:
            raise InvalidSignatureEnvelopeError(
                "Unable to deserialize signature envelope: Invalid WebAuthn signature envelope "
                f"size: expected at least 128 bytes, got {len(data)} bytes"
            )
        size = len(data) - 128
        authenticator_data, client_data_json = _split_webauthn_data(data[:size])
        tail = data[size:]
        return WebAuthnSignature(
            r=int.from_bytes(tail[0:32], "big"),
            s=int.from_bytes(tail[32:64], "big"),
            public_key_x=int.from_bytes(tail[64:96], "big"),
            public_key_y=int.from_bytes(tail[96:128], "big"),
            authenticator_data=to_hex(authenticator_data),
            client_data_json=client_data_json,
        )
    if type_id in (_KEYCHAIN_V1_TYPE, _KEYCHAIN_V2_TYPE):
        if len(data) <= 20:
            raise InvalidSignatureEnvelopeError(
                "Unable to deserialize signature envelope: keychain envelope is truncated"
            )
        inner = deserialize(data[20:])
        if not isinstance(inner, Signature | P256Signature | WebAuthnSignature):
            raise InvalidSignatureEnvelopeError(
                "Unable to deserialize signature envelope: keychain inner signature must be "
                "primitive"
            )
        return keychain_signature(
            user_address=to_hex(data[:20]),
            inner=inner,
            version="v1" if type_id == _KEYCHAIN_V1_TYPE else "v2",
        )
    if type_id == _MULTISIG_TYPE:
        return _deserialize_multisig(data)
    raise InvalidSignatureEnvelopeError(
        f"Unable to deserialize signature envelope: Unknown signature type identifier: 0x{type_id:02x}."
    )


def _split_webauthn_data(webauthn_data: bytes) -> tuple[bytes, str]:
    for split in range(37, len(webauthn_data)):
        try:
            candidate = webauthn_data[split:].decode()
        except UnicodeDecodeError:
            continue
        if candidate.startswith("{") and candidate.endswith("}"):
            try:
                json.loads(candidate)
            except ValueError:
                continue
            return webauthn_data[:split], candidate
    raise InvalidSignatureEnvelopeError(
        "Unable to deserialize signature envelope: Unable to parse WebAuthn metadata: could not "
        "extract valid authenticatorData and clientDataJSON"
    )


def _u256(value: int) -> bytes:
    return value.to_bytes(32, "big")


def p256_address(x: int, y: int) -> str:
    """Address derived from an uncompressed P256 public key."""
    return checksum(to_hex(keccak256(_u256(x) + _u256(y))[12:]))


def recover_address(digest: bytes, signature: Signature) -> str:
    """Recovers the checksummed signer address of a secp256k1 signature."""
    try:
        key = _EthKeysSignature(
            vrs=(y_parity(signature), signature.r, signature.s)
        ).recover_public_key_from_msg_hash(digest)
    except (BadSignature, ValidationError) as error:
        raise InvalidSignatureEnvelopeError(f"Unable to recover signer: {error}") from error
    return key.to_checksum_address()


def extract_address(envelope: SignatureEnvelope, payload: bytes, *, root: bool = False) -> str:
    """Returns the address that produced ``envelope`` over ``payload``.

    For keychain envelopes, ``root=True`` returns the account the access key
    acts for; otherwise the access key's own address.
    """
    match envelope:
        case KeychainSignature() | KeychainEnvelope():
            user_address, inner, _ = keychain_parts(envelope)
            if root:
                return user_address
            return extract_address(inner, payload)
        case Signature():
            return recover_address(payload, envelope)
        case P256Signature() | WebAuthnSignature():
            return p256_address(envelope.public_key_x, envelope.public_key_y)
        case MultisigSignature():
            # No single signer: the recovered sender is the multisig account.
            return envelope.account


def verify(envelope: SignatureEnvelope, *, payload: bytes, address: str) -> bool:
    """Verifies a primitive signature envelope against ``address``."""
    match envelope:
        case Signature():
            try:
                return is_equal(recover_address(payload, envelope), address)
            except InvalidSignatureEnvelopeError:
                return False
        case P256Signature():
            if not is_equal(p256_address(envelope.public_key_x, envelope.public_key_y), address):
                return False
            digest = hashlib.sha256(payload).digest() if envelope.prehash else payload
            return p256_verify(envelope, digest)
        case WebAuthnSignature():
            if not is_equal(p256_address(envelope.public_key_x, envelope.public_key_y), address):
                return False
            return _verify_webauthn(envelope, challenge=payload)
        case KeychainSignature() | KeychainEnvelope() | MultisigSignature():
            raise InvalidSignatureEnvelopeError(
                f'Unable to verify signature envelope of type "{_type(envelope)}".'
            )


def _verify_webauthn(envelope: WebAuthnSignature, *, challenge: bytes) -> bool:
    authenticator_data = to_bytes(envelope.authenticator_data)
    if len(authenticator_data) < 37:
        return False
    flags = authenticator_data[32]
    if flags & 0x01 != 0x01:
        return False
    if flags & 0x08 != 0x08 and flags & 0x10 == 0x10:
        return False
    try:
        client_data = json.loads(envelope.client_data_json)
    except ValueError:
        return False
    if not isinstance(client_data, dict) or client_data.get("type") != "webauthn.get":
        return False
    encoded_challenge = client_data.get("challenge")
    if not isinstance(encoded_challenge, str) or not encoded_challenge:
        return False
    try:
        decoded = _base64_decode(encoded_challenge)
    except ValueError:
        return False
    if decoded != challenge:
        return False
    payload = authenticator_data + hashlib.sha256(envelope.client_data_json.encode()).digest()
    return p256_verify(envelope, hashlib.sha256(payload).digest())


def _base64_decode(value: str) -> bytes:
    normalized = value.replace("-", "+").replace("_", "/")
    return base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)


def p256_verify(signature: P256Signature | WebAuthnSignature, digest: bytes) -> bool:
    """Verifies a low-s P256 signature over a 32-byte digest."""
    if len(digest) != 32 or not 0 < signature.s <= P256_N // 2 or not 0 < signature.r < P256_N:
        return False
    try:
        public_key = ec.EllipticCurvePublicNumbers(
            signature.public_key_x, signature.public_key_y, ec.SECP256R1()
        ).public_key()
        public_key.verify(
            encode_dss_signature(signature.r, signature.s),
            digest,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def to_rpc(envelope: SignatureEnvelope) -> dict[str, object] | str:
    """Formats an envelope as the JSON-RPC value Tempo nodes accept.

    Multisig envelopes are the RLP payload hex without the ``0x05`` type byte (ox ``MultisigRpc``).
    """
    match envelope:
        case Signature():
            return {
                "r": to_hex(_u256(envelope.r)),
                "s": to_hex(_u256(envelope.s)),
                "yParity": hex(y_parity(envelope)),
                "type": "secp256k1",
            }
        case P256Signature():
            return {
                "preHash": envelope.prehash,
                "pubKeyX": to_hex(_u256(envelope.public_key_x)),
                "pubKeyY": to_hex(_u256(envelope.public_key_y)),
                "r": to_hex(_u256(envelope.r)),
                "s": to_hex(_u256(envelope.s)),
                "type": "p256",
            }
        case WebAuthnSignature():
            return {
                "pubKeyX": to_hex(_u256(envelope.public_key_x)),
                "pubKeyY": to_hex(_u256(envelope.public_key_y)),
                "r": to_hex(_u256(envelope.r)),
                "s": to_hex(_u256(envelope.s)),
                "type": "webAuthn",
                "webauthnData": to_hex(
                    to_bytes(envelope.authenticator_data) + envelope.client_data_json.encode()
                ),
            }
        case KeychainSignature() | KeychainEnvelope():
            user_address, inner, version = keychain_parts(envelope)
            return {
                "type": "keychain",
                "userAddress": user_address,
                "signature": to_rpc(inner),
                "version": version,
            }
        case MultisigSignature():
            return to_hex(envelope.to_bytes()[1:])


def _type(envelope: AnyKeychainSignature | MultisigSignature) -> str:
    return "keychain" if isinstance(envelope, KeychainSignature) else envelope.type


# -- native multisig (TIP-1061) ----------------------------------------------------------------

MULTISIG_MAX_OWNERS: Final = 48
MULTISIG_MAX_SIGNATURES: Final = 8
MULTISIG_MAX_THRESHOLD: Final = 8
MULTISIG_MAX_OWNER_SIGNATURE_BYTES: Final = 2049

_MULTISIG_ZERO_SALT: Final = "0x" + "00" * 32
_MULTISIG_MAX_VERSION: Final = 2**64 - 1


class InvalidMultisigConfigError(ValueError):
    """ox ``MultisigConfig.InvalidConfigError``."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid native multisig config: {reason}.")


class InvalidMultisigApprovalError(InvalidSignatureEnvelopeError):
    """ox ``SignatureEnvelope.InvalidMultisigApprovalError``."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid native multisig approval: {reason}.")


def assert_multisig_config(config: MultisigConfig) -> None:
    """Validates a multisig config exactly like ox ``MultisigConfig.assert``."""
    if len(to_bytes(config.salt)) != 32:
        raise InvalidMultisigConfigError("salt must be 32 bytes")
    if not 0 <= config.version <= _MULTISIG_MAX_VERSION:
        raise InvalidMultisigConfigError("version must be an unsigned 64-bit integer")
    if not config.owners:
        raise InvalidMultisigConfigError("owners cannot be empty")
    if len(config.owners) > MULTISIG_MAX_OWNERS:
        raise InvalidMultisigConfigError("too many owners")
    if config.threshold < 1:
        raise InvalidMultisigConfigError("threshold cannot be zero")
    if config.threshold > MULTISIG_MAX_THRESHOLD:
        raise InvalidMultisigConfigError("threshold exceeds max threshold")
    previous: int | None = None
    for owner in config.owners:
        if not is_address(owner.owner, strict=False) or _address_int(owner.owner) == 0:
            raise InvalidMultisigConfigError("owner cannot be zero")
        if owner.weight < 1:
            raise InvalidMultisigConfigError("owner weight cannot be zero")
        current = _address_int(owner.owner)
        if previous is not None and previous >= current:
            raise InvalidMultisigConfigError("owners must be strictly ascending")
        previous = current
    weights = [owner.weight for owner in config.owners]
    total = sum(weights)
    if total > 0xFF:
        raise InvalidMultisigConfigError("total owner weight exceeds u8 max")
    if config.threshold > total:
        raise InvalidMultisigConfigError("threshold exceeds total owner weight")
    if config.threshold > sum(sorted(weights, reverse=True)[:MULTISIG_MAX_SIGNATURES]):
        raise InvalidMultisigConfigError(
            f"threshold exceeds weight reachable by {MULTISIG_MAX_SIGNATURES} owner signatures"
        )


def multisig_config_to_tuple(config: MultisigConfig) -> list[Any]:
    """The config's RLP tuple ``[salt, version, threshold, [[owner, weight], ...]]``."""
    assert_multisig_config(config)
    return [
        to_bytes(_pad_salt(config.salt)),
        uint_to_bytes(config.version),
        uint_to_bytes(config.threshold),
        [[to_bytes(owner.owner), uint_to_bytes(owner.weight)] for owner in config.owners],
    ]


def multisig_config_from_tuple(value: Any) -> MultisigConfig:
    """Parses a config RLP tuple, rejecting non-canonical integers (ox ``fromTuple``)."""
    if not (isinstance(value, list) and len(value) == 4):
        raise InvalidMultisigConfigError("invalid config RLP tuple")
    salt, version, threshold, owners = value
    if (
        not isinstance(salt, bytes)
        or len(salt) != 32
        or not _canonical_uint(version, 8)
        or not _canonical_uint(threshold, 1)
        or not isinstance(owners, list)
        or any(
            not isinstance(owner, list)
            or len(owner) != 2
            or not isinstance(owner[0], bytes)
            or len(owner[0]) != 20
            or not _canonical_uint(owner[1], 1)
            for owner in owners
        )
    ):
        raise InvalidMultisigConfigError("invalid config RLP tuple")
    config = MultisigConfig(
        owners=tuple(
            MultisigOwner(owner=to_hex(owner), weight=int.from_bytes(weight, "big"))
            for owner, weight in owners
        ),
        threshold=int.from_bytes(threshold, "big"),
        salt=to_hex(salt),
        version=int.from_bytes(version, "big"),
    )
    assert_multisig_config(config)
    return config


def assert_multisig(envelope: MultisigSignature) -> None:
    """Validates a multisig envelope like ox ``SignatureEnvelope.assert``."""
    if not is_address(envelope.account, strict=False):
        raise InvalidMultisigApprovalError("multisig account is invalid")
    if _address_int(envelope.account) == 0:
        raise InvalidMultisigApprovalError("multisig account cannot be zero")
    if not envelope.signatures:
        raise InvalidMultisigApprovalError("multisig signatures cannot be empty")
    if len(envelope.signatures) > MULTISIG_MAX_SIGNATURES:
        raise InvalidMultisigApprovalError(f"multisig signatures exceed {MULTISIG_MAX_SIGNATURES}")
    assert_multisig_config(envelope.config)
    if envelope.config.version == 0 and any(
        is_equal(owner.owner, envelope.account) for owner in envelope.config.owners
    ):
        raise InvalidMultisigApprovalError("initial account cannot be an owner")
    for signature in envelope.signatures:
        if not isinstance(signature, Signature | P256Signature | WebAuthnSignature):
            raise InvalidMultisigApprovalError("owner approvals must be primitive signatures")
        if len(signature.to_bytes()) > MULTISIG_MAX_OWNER_SIGNATURE_BYTES:
            raise InvalidMultisigApprovalError(
                f"multisig owner signature exceeds {MULTISIG_MAX_OWNER_SIGNATURE_BYTES} bytes"
            )


def _multisig_rlp(envelope: MultisigSignature) -> bytes:
    return rlp_encode(
        [
            to_bytes(envelope.account),
            multisig_config_to_tuple(envelope.config),
            [signature.to_bytes() for signature in envelope.signatures],
        ]
    )


def _deserialize_multisig(data: bytes) -> MultisigSignature:
    def invalid(reason: str) -> InvalidSignatureEnvelopeError:
        return InvalidSignatureEnvelopeError(f"Unable to deserialize signature envelope: {reason}")

    try:
        decoded = rlp_decode(data)
    except Exception as error:
        raise invalid("invalid multisig wire shape: malformed RLP") from error
    if not isinstance(decoded, list) or len(decoded) != 3:
        raise invalid("invalid multisig wire shape: expected exactly three fields")
    account, config, signatures = decoded
    if not isinstance(account, bytes) or len(account) != 20:
        raise invalid("invalid multisig account")
    if not isinstance(config, list):
        raise invalid("invalid multisig config")
    if (
        not isinstance(signatures, list)
        or not signatures
        or len(signatures) > MULTISIG_MAX_SIGNATURES
    ):
        raise invalid("invalid multisig signatures list")
    approvals: list[PrimitiveSignature] = []
    for raw in signatures:
        if not isinstance(raw, bytes) or not raw or len(raw) > MULTISIG_MAX_OWNER_SIGNATURE_BYTES:
            raise invalid("invalid multisig owner signature")
        if len(raw) != 65 and raw[0] not in (_P256_TYPE, _WEBAUTHN_TYPE):
            raise invalid("owner approvals must be primitive signatures")
        approval = deserialize(raw)
        if not isinstance(
            approval, Signature | P256Signature | WebAuthnSignature
        ):  # pragma: no cover
            raise invalid("owner approvals must be primitive signatures")
        approvals.append(approval)
    envelope = MultisigSignature(
        account=to_hex(account),
        config=multisig_config_from_tuple(config),
        signatures=tuple(approvals),
    )
    assert_multisig(envelope)
    return envelope


def _canonical_uint(value: Any, size: int) -> bool:
    return isinstance(value, bytes) and len(value) <= size and not value.startswith(b"\x00")


def _address_int(address: str) -> int:
    return int.from_bytes(to_bytes(address), "big")


def _pad_salt(salt: str) -> str:
    return to_hex(to_bytes(salt).rjust(32, b"\x00"))
