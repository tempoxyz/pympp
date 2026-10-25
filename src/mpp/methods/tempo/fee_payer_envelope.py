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
        signatureEnvelope        # serialized sender signature; local cosigning
                                 # currently supports only 65-byte secp256k1
    ])
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

import attrs
import rlp

if TYPE_CHECKING:
    from pytempo import TempoTransaction

FEE_PAYER_ENVELOPE_TYPE_ID = 0x78


@runtime_checkable
class _HasRlpPayload(Protocol):
    """Anything exposing ``as_rlp_payload()`` (pytempo's ``SignedKeyAuthorization``
    or the :class:`_RawSignedKeyAuthorization` wrapper)."""

    def as_rlp_payload(self) -> list: ...


@attrs.frozen
class _RawSignedKeyAuthorization:
    """Holds a decoded ``keyAuthorization`` field and re-emits it unchanged.

    pytempo includes ``key_authorization.as_rlp_payload()`` in the signing hash
    and final encoding, so the full payload must round-trip intact regardless of
    which optional fields it carries (legacy or T6).
    """

    _rlp: bytes

    def as_rlp_payload(self) -> list:
        return rlp.decode(self._rlp)


def _key_authorization_payload(key_authorization: object) -> list:
    """Return the RLP-list payload for a transaction's ``keyAuthorization`` field.

    Accepts an object exposing ``as_rlp_payload()``, raw RLP bytes, or a
    pre-decoded list.
    """
    if isinstance(key_authorization, _HasRlpPayload):
        payload = key_authorization.as_rlp_payload()
    elif isinstance(key_authorization, (bytes, bytearray)):
        payload = rlp.decode(bytes(key_authorization))
    elif isinstance(key_authorization, list):
        payload = key_authorization
    else:
        raise TypeError(f"Unsupported key_authorization type: {type(key_authorization)!r}")
    if not isinstance(payload, list):
        raise TypeError("key_authorization payload must be an RLP list")
    return payload


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
        fields.append(_key_authorization_payload(signed_tx.key_authorization))
        fields.append(sig_bytes)
    else:
        fields.append(sig_bytes)

    return bytes([FEE_PAYER_ENVELOPE_TYPE_ID]) + rlp.encode(fields)


def decode_fee_payer_envelope(
    data: bytes,
) -> tuple[list, bytes, bytes, _RawSignedKeyAuthorization | None]:
    """Decode a 0x78 fee payer envelope.

    Args:
        data: Raw bytes starting with ``0x78``.

    Returns:
        Tuple of (decoded RLP fields, sender_address bytes,
        sender_signature bytes, key authorization passthrough or None).

    Raises:
        ValueError: If the data doesn't start with ``0x78`` or is malformed.
    """
    if not data or data[0] != FEE_PAYER_ENVELOPE_TYPE_ID:
        raise ValueError("Not a fee payer envelope (expected 0x78 prefix)")

    decoded = rlp.decode(data[1:])
    # 14 fields = no key_authorization; 15 = key_authorization present.
    if not isinstance(decoded, list) or len(decoded) not in (14, 15):
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


def _decode_signed_key_authorization(rlp_fields: list) -> _RawSignedKeyAuthorization:
    """Validate and wrap a decoded ``[authorization_payload, signature]`` field.

    The signature is preserved as-is (any non-empty serialized signature
    envelope), not parsed, so it is never assumed to be 65-byte secp256k1.
    """
    if not isinstance(rlp_fields, list) or len(rlp_fields) != 2:
        raise ValueError("Malformed key_authorization field")
    if not isinstance(rlp_fields[0], list):
        raise ValueError("Malformed key_authorization payload")
    sig_bytes = rlp_fields[1]
    if not isinstance(sig_bytes, bytes) or len(sig_bytes) == 0:
        raise ValueError("Malformed key_authorization signature")

    return _RawSignedKeyAuthorization(rlp.encode(rlp_fields))
