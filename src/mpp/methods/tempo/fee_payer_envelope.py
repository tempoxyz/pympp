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

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import attrs

from mpp._typing import is_list
from mpp.methods.tempo import _rlp as rlp

if TYPE_CHECKING:
    # pytempo ships no type information.
    from pytempo import TempoTransaction  # pyright: ignore[reportMissingTypeStubs]

FEE_PAYER_ENVELOPE_TYPE_ID = 0x78


@runtime_checkable
class _HasRlpPayload(Protocol):
    """Anything exposing ``as_rlp_payload()`` (pytempo's ``SignedKeyAuthorization``
    or the :class:`_RawSignedKeyAuthorization` wrapper)."""

    def as_rlp_payload(self) -> list[Any]: ...


@attrs.frozen
class _RawSignedKeyAuthorization:
    """Holds a decoded ``keyAuthorization`` field and re-emits it unchanged.

    pytempo includes ``key_authorization.as_rlp_payload()`` in the signing hash
    and final encoding, so the full payload must round-trip intact regardless of
    which optional fields it carries (legacy or T6).
    """

    _rlp: bytes

    def as_rlp_payload(self) -> list[Any]:
        return rlp.decode(self._rlp)


def _key_authorization_payload(key_authorization: object) -> list[Any]:
    """Return the RLP-list payload for a transaction's ``keyAuthorization`` field.

    Accepts an object exposing ``as_rlp_payload()``, raw RLP bytes, or a
    pre-decoded list.
    """
    payload: object
    if isinstance(key_authorization, _HasRlpPayload):
        payload = key_authorization.as_rlp_payload()
    elif isinstance(key_authorization, (bytes, bytearray)):
        payload = rlp.decode(bytes(key_authorization))
    elif is_list(key_authorization):
        payload = key_authorization
    else:
        raise TypeError(f"Unsupported key_authorization type: {type(key_authorization)!r}")
    if not is_list(payload):
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
    # pytempo's transaction fields are partially untyped.
    tx: Any = signed_tx
    sender_sig = tx.sender_signature
    sig_bytes = sender_sig.to_bytes() if hasattr(sender_sig, "to_bytes") else bytes(sender_sig)  # type: ignore[arg-type]

    sender_addr = bytes(tx.sender_address)  # type: ignore[arg-type]

    fields: list[Any] = [
        tx.chain_id,
        tx.max_priority_fee_per_gas,
        tx.max_fee_per_gas,
        tx.gas_limit,
        [c.as_rlp_list() for c in tx.calls],
        [a.as_rlp_list() for a in tx.access_list],
        tx.nonce_key,
        tx.nonce,
        tx._encode_optional_uint(tx.valid_before),
        tx._encode_optional_uint(tx.valid_after),
        bytes(tx.fee_token) if tx.fee_token else b"",
        sender_addr,
        list(tx.tempo_authorization_list),
    ]

    if tx.key_authorization is not None:
        fields.append(_key_authorization_payload(tx.key_authorization))
        fields.append(sig_bytes)
    else:
        fields.append(sig_bytes)

    return bytes([FEE_PAYER_ENVELOPE_TYPE_ID]) + rlp.encode(fields)


# chain_id, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, nonce_key,
# nonce, valid_before, valid_after, fee_token, sender_address.
_SCALAR_FIELDS = (0, 1, 2, 3, 6, 7, 8, 9, 10, 11)


def decode_fee_payer_envelope(
    data: bytes,
) -> tuple[list[Any], bytes, bytes, _RawSignedKeyAuthorization | None]:
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

    try:
        decoded = rlp.decode(data[1:])
    except (rlp.RLPException, RecursionError) as error:
        raise ValueError("Malformed fee payer envelope") from error
    # 14 fields = no key_authorization; 15 = key_authorization present.
    if not is_list(decoded) or len(decoded) not in (14, 15):
        raise ValueError("Malformed fee payer envelope")

    # Every field but calls, access list, authorization list and key
    # authorization is a scalar; callers read them as bytes.
    if not all(isinstance(decoded[i], bytes) for i in _SCALAR_FIELDS + (len(decoded) - 1,)):
        raise ValueError("Malformed fee payer envelope")
    sender_address = decoded[11]
    sender_signature = decoded[-1]

    # 15 fields = key_authorization present (index 13), signature at 14
    # 14 fields = no key_authorization, signature at 13
    if len(decoded) == 15:
        key_authorization = _decode_signed_key_authorization(decoded[13])
    else:
        key_authorization = None

    return decoded, sender_address, sender_signature, key_authorization


def _decode_signed_key_authorization(rlp_fields: Any) -> _RawSignedKeyAuthorization:
    """Validate and wrap a decoded ``[authorization_payload, signature]`` field.

    The signature is preserved as-is (any non-empty serialized signature
    envelope), not parsed, so it is never assumed to be 65-byte secp256k1.
    """
    if not is_list(rlp_fields) or len(rlp_fields) != 2:
        raise ValueError("Malformed key_authorization field")
    if not is_list(rlp_fields[0]):
        raise ValueError("Malformed key_authorization payload")
    sig_bytes = rlp_fields[1]
    if not isinstance(sig_bytes, bytes) or len(sig_bytes) == 0:
        raise ValueError("Malformed key_authorization signature")

    return _RawSignedKeyAuthorization(rlp.encode(rlp_fields))
