"""Fee payer envelope encoding/decoding (0x78 wire format).

The 0x78 envelope is a non-broadcastable wire format for handing off a
sender-signed transaction to a fee payer, who co-signs and broadcasts as 0x76.

Wire format::

    0x78 || RLP([
        chainId, maxPriorityFeePerGas, maxFeePerGas, gasLimit,
        calls, accessList, nonceKey, nonce,
        validBefore?, validAfter?, feeToken?,
        senderAddress,           # 20 bytes (replaces feePayerSignature slot)
        authorizationList, keyAuthorization?,
        signatureEnvelope        # sender's raw 65-byte r||s||v
    ])
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import rlp

if TYPE_CHECKING:
    from pytempo import SignedKeyAuthorization, TempoTransaction

FEE_PAYER_ENVELOPE_TYPE_ID = 0x78


def encode_fee_payer_envelope(signed_tx: TempoTransaction) -> bytes:
    """Encode a sender-signed transaction as a 0x78 fee payer envelope.

    Args:
        signed_tx: A TempoTransaction that has been signed by the sender
            (``sender_signature`` and ``sender_address`` must be set).

    Returns:
        Raw bytes: ``0x78 || RLP([fields...])``.
    """
    sender_sig = signed_tx.sender_signature
    sig_bytes = sender_sig.to_bytes() if hasattr(sender_sig, "to_bytes") else bytes(sender_sig)  # type: ignore[arg-type]

    sender_addr = bytes(signed_tx.sender_address)  # type: ignore[arg-type]

    fields: list = [
        signed_tx.chain_id,
        signed_tx.max_priority_fee_per_gas,
        signed_tx.max_fee_per_gas,
        signed_tx.gas_limit,
        [c.as_rlp_list() for c in signed_tx.calls],
        [a.as_rlp_list() for a in signed_tx.access_list],
        signed_tx.nonce_key,
        signed_tx.nonce,
        signed_tx._encode_optional_uint(signed_tx.valid_before),
        signed_tx._encode_optional_uint(signed_tx.valid_after),
        bytes(signed_tx.fee_token) if signed_tx.fee_token else b"",
        sender_addr,
        list(signed_tx.tempo_authorization_list),
    ]

    if signed_tx.key_authorization is not None:
        fields.append(rlp.decode(signed_tx.key_authorization))
        fields.append(sig_bytes)
    else:
        fields.append(sig_bytes)

    return bytes([FEE_PAYER_ENVELOPE_TYPE_ID]) + rlp.encode(fields)


def decode_fee_payer_envelope(
    data: bytes,
) -> tuple[list, bytes, bytes, SignedKeyAuthorization | None]:
    """Decode a 0x78 fee payer envelope.

    Args:
        data: Raw bytes starting with ``0x78``.

    Returns:
        Tuple of (decoded RLP fields, sender_address bytes,
        sender_signature bytes, SignedKeyAuthorization or None).

    Raises:
        ValueError: If the data doesn't start with ``0x78`` or is malformed.
    """
    if not data or data[0] != FEE_PAYER_ENVELOPE_TYPE_ID:
        raise ValueError("Not a fee payer envelope (expected 0x78 prefix)")

    decoded = rlp.decode(data[1:])
    if not isinstance(decoded, list) or len(decoded) < 14:
        raise ValueError("Malformed fee payer envelope")

    sender_address = decoded[11]
    sender_signature = decoded[-1]

    # 15 fields = key_authorization present (index 13), signature at 14
    # 14 fields = no key_authorization, signature at 13
    if len(decoded) == 15:
        key_authorization = _decode_signed_key_authorization(decoded[13])
    else:
        key_authorization = None

    return decoded, bytes(sender_address), bytes(sender_signature), key_authorization  # type: ignore[arg-type]


def _decode_signed_key_authorization(rlp_fields: list) -> SignedKeyAuthorization:
    """Reconstruct a SignedKeyAuthorization from decoded RLP fields."""
    from pytempo import KeyAuthorization, SignatureType, SignedKeyAuthorization
    from pytempo.models import Signature

    auth_fields = rlp_fields[0]
    sig_bytes = bytes(rlp_fields[1])

    chain_id = int.from_bytes(auth_fields[0], "big") if auth_fields[0] else 0
    key_type = SignatureType(int.from_bytes(auth_fields[1], "big") if auth_fields[1] else 0)
    key_id = bytes(auth_fields[2])

    expiry = (
        int.from_bytes(auth_fields[3], "big") if len(auth_fields) > 3 and auth_fields[3] else None
    )

    authorization = KeyAuthorization(
        key_id=key_id,
        chain_id=chain_id,
        key_type=key_type,
        expiry=expiry,
    )

    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:64], "big")
    v = sig_bytes[64]

    return SignedKeyAuthorization(authorization=authorization, signature=Signature(r=r, s=s, v=v))
