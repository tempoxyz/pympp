"""TIP-1034 voucher and close-authorization EIP-712 helpers (mppx precompile/Voucher.ts).

Vouchers are EIP-712 `Voucher(bytes32 channelId,uint96 cumulativeAmount)` messages in
the `TIP20 Channel Reserve` domain; cooperative closes sign the distinct
`CloseAuthorization` type. TIP-1020 primitive secp256k1 signatures in their
canonical 65-byte `r || s || v` form (`v` 27 or 28) are produced and accepted. A
TIP-1166 configurable account signer produces `0x05` configurable account
signatures, which verification accepts only when it opts in (`configurable=True`).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from eth_abi.abi import encode
from eth_hash.auto import keccak

from mpp.methods.tempo.session._configurable import (
    SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT,
    is_configurable_signature,
    is_zero_hash,
    verify_configurable_signature,
)
from mpp.methods.tempo.session._protocol import ESCROW_ADDRESS, SignedVoucher, uint96

DOMAIN_NAME = "TIP20 Channel Reserve"
"""Must match the on-chain TIP-20 channel reserve `DOMAIN_SEPARATOR` name."""
DOMAIN_VERSION = "1"
"""Must match the on-chain TIP-20 channel reserve `DOMAIN_SEPARATOR` version."""

_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)
VOUCHER_TYPEHASH = keccak(b"Voucher(bytes32 channelId,uint96 cumulativeAmount)")
CLOSE_AUTHORIZATION_TYPEHASH = keccak(
    b"CloseAuthorization(bytes32 channelId,uint96 cumulativeAmount)"
)


@runtime_checkable
class HashSigner(Protocol):
    """An account that signs a raw 32-byte digest (such as `TempoAccount`)."""

    def sign_hash(self, msg_hash: bytes) -> bytes: ...


def domain_separator(escrow: str, chain_id: int) -> bytes:
    """The EIP-712 domain separator, as the precompile's `domainSeparator()`."""
    return keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                _DOMAIN_TYPEHASH,
                keccak(DOMAIN_NAME.encode()),
                keccak(DOMAIN_VERSION.encode()),
                chain_id,
                escrow,
            ],
        )
    )


def _typed_digest(typehash: bytes, escrow: str, chain_id: int, channel_id: str, amount: int) -> str:
    channel = bytes.fromhex(channel_id.removeprefix("0x"))
    if len(channel) != 32:
        raise ValueError("channel_id must be 32 bytes")
    struct_hash = keccak(
        encode(["bytes32", "bytes32", "uint96"], [typehash, channel, uint96(amount)])
    )
    return "0x" + keccak(b"\x19\x01" + domain_separator(escrow, chain_id) + struct_hash).hex()


def voucher_digest(
    *, channel_id: str, cumulative_amount: int, chain_id: int, escrow: str = ESCROW_ADDRESS
) -> str:
    """The EIP-712 digest a voucher signs (the precompile's `getVoucherDigest`)."""
    return _typed_digest(VOUCHER_TYPEHASH, escrow, chain_id, channel_id, cumulative_amount)


def close_authorization_digest(
    *, channel_id: str, cumulative_amount: int, chain_id: int, escrow: str = ESCROW_ADDRESS
) -> str:
    """The EIP-712 digest a cooperative close authorization signs."""
    return _typed_digest(
        CLOSE_AUTHORIZATION_TYPEHASH, escrow, chain_id, channel_id, cumulative_amount
    )


def _sign_digest(account: Any, digest: str) -> str:
    msg_hash = bytes.fromhex(digest.removeprefix("0x"))
    if isinstance(account, HashSigner):
        signature = account.sign_hash(msg_hash)
    elif hasattr(account, "unsafe_sign_hash"):
        signed = account.unsafe_sign_hash(msg_hash)
        signature = signed.r.to_bytes(32, "big") + signed.s.to_bytes(32, "big") + bytes([signed.v])
    else:
        raise TypeError("account must provide sign_hash() or unsafe_sign_hash()")
    if len(signature) != 65 and signature[:1] == bytes([SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT]):
        # A TIP-1166 configurable account signature carries its owners' approvals.
        return "0x" + bytes(signature).hex()
    if len(signature) != 65:
        raise ValueError(
            "TIP-1034 vouchers require a TIP-1020 primitive signature; received a "
            f"{len(signature)}-byte signature."
        )
    v = signature[64]
    if v in (0, 1):
        v += 27
    return "0x" + (signature[:64] + bytes([v])).hex()


def sign_voucher(
    account: Any,
    *,
    channel_id: str,
    cumulative_amount: int,
    chain_id: int,
    escrow: str = ESCROW_ADDRESS,
) -> str:
    """Sign a voucher; returns the canonical 65-byte signature as 0x-hex.

    `account` is a `TempoAccount` (or any object with `sign_hash(digest)`) or an
    eth-account `LocalAccount`. A TIP-1166 `ConfigurableAccount` returns its `0x05`
    configurable account signature instead.
    """
    digest = voucher_digest(
        channel_id=channel_id, cumulative_amount=cumulative_amount, chain_id=chain_id, escrow=escrow
    )
    return _sign_digest(account, digest)


def sign_close_authorization(
    account: Any,
    *,
    channel_id: str,
    cumulative_amount: int,
    chain_id: int,
    escrow: str = ESCROW_ADDRESS,
) -> str:
    """Sign the distinct authorization for cooperatively closing a channel."""
    digest = close_authorization_digest(
        channel_id=channel_id, cumulative_amount=cumulative_amount, chain_id=chain_id, escrow=escrow
    )
    return _sign_digest(account, digest)


def _recover_canonical(signature: str, digest: str) -> str | None:
    """Recover the signer of a canonical primitive secp256k1 signature, else None.

    Keychain wrappers, multisig, magic-suffixed and non-canonical encodings
    (`v` other than 27 or 28) are rejected, as ox's `SignatureEnvelope` round trip
    does in mppx. P256 and WebAuthn primitive signatures are not supported yet.
    """
    from eth_account import Account

    try:
        raw = bytes.fromhex(signature.removeprefix("0x"))
    except ValueError:
        return None
    if not signature.startswith("0x") or len(raw) != 65 or raw[64] not in (27, 28):
        return None
    try:
        return Account._recover_hash(  # pyright: ignore[reportPrivateUsage]
            bytes.fromhex(digest.removeprefix("0x")), signature=raw
        )
    except Exception:
        return None


def _verify_signer_signature(
    signature: str,
    digest: str,
    expected_signer: str,
    *,
    configurable: bool,
    opening_commitment: str | None,
) -> bool:
    """Apply the TIP-1034 and TIP-1166 signer rules to one signature.

    A `0x05` configurable account signature counts only with `configurable`. A nonzero
    `opening_commitment` (the config commitment the escrow cached at open) rejects
    primitive signatures, as the escrow does.
    """
    if is_configurable_signature(signature):
        if not configurable:
            return False
        try:
            inner = bytes.fromhex(digest.removeprefix("0x"))
        except ValueError:
            return False
        return verify_configurable_signature(signature, inner, expected_signer, opening_commitment)
    if not is_zero_hash(opening_commitment):
        return False
    signer = _recover_canonical(signature, digest)
    return signer is not None and signer.lower() == expected_signer.lower()


def verify_voucher(
    escrow: str,
    chain_id: int,
    voucher: SignedVoucher,
    expected_signer: str,
    *,
    configurable: bool = False,
    opening_commitment: str | None = None,
) -> bool:
    """Return whether `voucher` carries a valid signature by `expected_signer`.

    By default only canonical TIP-1020 primitive signatures are accepted. With
    `configurable`, a TIP-1166 configurable account (`0x05`) signature is accepted when
    it names `expected_signer`, its owner approvals reach the threshold, and its config
    commits to `opening_commitment` or, when the opening commitment is absent or zero, is the
    version-zero config that derives `expected_signer`. A nonzero `opening_commitment`
    rejects primitive signatures.
    """
    try:
        digest = voucher_digest(
            channel_id=voucher.channel_id,
            cumulative_amount=voucher.cumulative_amount,
            chain_id=chain_id,
            escrow=escrow,
        )
        commitment_zero = is_zero_hash(opening_commitment)
    except Exception:
        return False
    return _verify_signer_signature(
        voucher.signature,
        digest,
        expected_signer,
        configurable=configurable,
        opening_commitment=None if commitment_zero else opening_commitment,
    )


def verify_close_authorization(
    escrow: str,
    chain_id: int,
    authorization: SignedVoucher,
    expected_signers: Sequence[str],
    *,
    configurable: bool = False,
    opening_commitment: str | None = None,
) -> bool:
    """Return whether a close-authorization signature belongs to one of `expected_signers`.

    `configurable` and `opening_commitment` apply the TIP-1166 rules of :func:`verify_voucher`
    to the channel's voucher signer. The payer's own close authorization stays a
    primitive signature: pass the opening commitment only when checking the voucher signer.
    """
    try:
        digest = close_authorization_digest(
            channel_id=authorization.channel_id,
            cumulative_amount=authorization.cumulative_amount,
            chain_id=chain_id,
            escrow=escrow,
        )
        commitment_zero = is_zero_hash(opening_commitment)
    except Exception:
        return False
    return any(
        _verify_signer_signature(
            authorization.signature,
            digest,
            expected,
            configurable=configurable,
            opening_commitment=None if commitment_zero else opening_commitment,
        )
        for expected in expected_signers
    )


def parse_voucher_from_payload(
    channel_id: str, cumulative_amount: str, signature: str
) -> SignedVoucher:
    """Build a `SignedVoucher` from credential payload fields, checking the uint96 range."""
    return SignedVoucher(
        channel_id=channel_id,
        cumulative_amount=uint96(int(cumulative_amount)),
        signature=signature,
    )
