"""TIP-1034 channel ID and expiring-nonce hashing (mppx src/tempo/session/precompile/Channel.ts)."""

from __future__ import annotations

from typing import Any

from eth_abi.abi import encode
from eth_hash.auto import keccak

from mpp.methods.tempo.session.protocol import ESCROW_ADDRESS, ChannelDescriptor


def resolve_authorized_signer(descriptor: ChannelDescriptor) -> str:
    """The descriptor's effective voucher signer; the zero address delegates to the payer."""
    if int(descriptor.authorized_signer, 16) == 0:
        return descriptor.payer
    return descriptor.authorized_signer


def compute_channel_id(
    descriptor: ChannelDescriptor, *, chain_id: int, escrow: str = ESCROW_ADDRESS
) -> str:
    """Compute the TIP-1034 channel ID for a descriptor, as the precompile's `computeChannelId`.

    `keccak256(abi.encode(payer, payee, operator, token, salt, authorizedSigner,
    expiringNonceHash, escrow, chainId))`.
    """
    encoded = encode(
        [
            "address",
            "address",
            "address",
            "address",
            "bytes32",
            "address",
            "bytes32",
            "address",
            "uint256",
        ],
        [
            descriptor.payer,
            descriptor.payee,
            descriptor.operator,
            descriptor.token,
            bytes.fromhex(descriptor.salt.removeprefix("0x")),
            descriptor.authorized_signer,
            bytes.fromhex(descriptor.expiring_nonce_hash.removeprefix("0x")),
            escrow,
            chain_id,
        ],
    )
    return "0x" + keccak(encoded).hex()


def _decode_tempo_transaction(raw_tx: str) -> tuple[int, list[Any]]:
    """Split a serialized 0x76 or 0x78 Tempo transaction into its type and RLP fields."""
    from mpp._typing import is_list
    from mpp.methods.tempo import _rlp as rlp

    try:
        tx_bytes = bytes.fromhex(raw_tx.removeprefix("0x"))
        if tx_bytes[:1] not in (b"\x76", b"\x78"):
            raise ValueError("not a Tempo transaction")
        fields = rlp.decode(tx_bytes[1:])
    except Exception as error:
        raise ValueError("Only Tempo (0x76/0x78) transactions are supported") from error
    if not is_list(fields) or len(fields) not in (13, 14, 15):
        raise ValueError("Malformed Tempo transaction")
    return tx_bytes[0], list(fields)


def sender_signing_preimage(raw_tx: str, *, fee_payer: bool | None = None) -> bytes:
    """The bytes a Tempo transaction's sender signs (ox `TxEnvelopeTempo.encodeForSigning`).

    A sponsored transaction (a 0x78 envelope, a co-signed 0x76, or `fee_payer=True`)
    commits to the fee-payer placeholder instead of a fee token, so fee-payer
    co-signing never changes it.
    """
    from mpp.methods.tempo import _rlp as rlp

    type_id, fields = _decode_tempo_transaction(raw_tx)
    # Drop the sender signature: unsigned bodies have 13 or 14 fields
    # (with a key authorization), signed ones one more.
    has_key_authorization = len(fields) == 15 or (
        len(fields) == 14 and not isinstance(fields[13], bytes)
    )
    body = fields[: 14 if has_key_authorization else 13]
    sponsored = type_id == 0x78 or fields[11] != b""
    if fee_payer is not None:
        sponsored = sponsored or fee_payer
    preimage = [
        *body[:10],
        b"" if sponsored else body[10],
        b"\x00" if sponsored else b"",
        *body[12:],
    ]
    return b"\x76" + rlp.encode(preimage)


def expiring_nonce_hash(raw_signed_tx: str, sender: str, *, fee_payer: bool | None = None) -> str:
    """Compute the TIP-1034 `expiringNonceHash` of a channel-opening transaction.

    `keccak256(encodeForSigning(tx) || sender)`, the node's consensus preimage
    (mppx `Channel.computeExpiringNonceHash` over
    `transactionForExpiringNonceHash`). `fee_payer=True` hashes the
    transaction as sponsored even when it carries no fee-payer marker, as mppx
    does when the server sponsors fees.
    """
    sender_bytes = bytes.fromhex(sender.removeprefix("0x"))
    if len(sender_bytes) != 20:
        raise ValueError("sender must be a 20-byte address")
    preimage = sender_signing_preimage(raw_signed_tx, fee_payer=fee_payer)
    return "0x" + keccak(preimage + sender_bytes).hex()
