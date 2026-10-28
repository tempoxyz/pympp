"""TIP-1034 voucher and close-authorization EIP-712 helpers (mppx precompile/Voucher.ts).

Vouchers are EIP-712 `Voucher(bytes32 channelId,uint96 cumulativeAmount)` messages in
the `TIP20 Channel Reserve` domain; cooperative closes sign the distinct
`CloseAuthorization` type. Only TIP-1020 primitive secp256k1 signatures in their
canonical 65-byte `r || s || v` form (`v` 27 or 28) are produced and accepted.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from eth_abi.abi import encode
from eth_hash.auto import keccak

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
    eth-account `LocalAccount`.
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


def verify_voucher(
    escrow: str, chain_id: int, voucher: SignedVoucher, expected_signer: str
) -> bool:
    """Return whether `voucher` carries a canonical signature by `expected_signer`."""
    try:
        digest = voucher_digest(
            channel_id=voucher.channel_id,
            cumulative_amount=voucher.cumulative_amount,
            chain_id=chain_id,
            escrow=escrow,
        )
    except Exception:
        return False
    signer = _recover_canonical(voucher.signature, digest)
    return signer is not None and signer.lower() == expected_signer.lower()


def verify_close_authorization(
    escrow: str, chain_id: int, authorization: SignedVoucher, expected_signers: Sequence[str]
) -> bool:
    """Return whether a close-authorization signature belongs to one of `expected_signers`."""
    try:
        digest = close_authorization_digest(
            channel_id=authorization.channel_id,
            cumulative_amount=authorization.cumulative_amount,
            chain_id=chain_id,
            escrow=escrow,
        )
    except Exception:
        return False
    signer = _recover_canonical(authorization.signature, digest)
    return signer is not None and any(signer.lower() == s.lower() for s in expected_signers)


def parse_voucher_from_payload(
    channel_id: str, cumulative_amount: str, signature: str
) -> SignedVoucher:
    """Build a `SignedVoucher` from credential payload fields, checking the uint96 range."""
    return SignedVoucher(
        channel_id=channel_id,
        cumulative_amount=uint96(int(cumulative_amount)),
        signature=signature,
    )
