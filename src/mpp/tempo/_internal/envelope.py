"""Tempo transaction envelopes (ox ``TxEnvelopeTempo``) on top of pytempo.

pytempo models, hashes, signs and encodes Tempo transactions (:class:`pytempo.TempoTransaction`,
type ``0x76``, including the ``0x78`` fee-payer signing hash). This module adds what pytempo
lacks:

- decoding ``0x76`` transactions and ``0x78`` fee-payer envelopes into pytempo models,
- encoding the ``0x78`` envelope a client hands to its sponsor
  (``0x78 || rlp([..., sender, authorizationList, keyAuthorization?, signature])``),
- key authorizations pytempo cannot model (call scopes, periodic limits, P256, WebAuthn or
  multisig keys and signatures), carried through unchanged and formatted for JSON-RPC,
- ox's validation rules and messages.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any, Final, Protocol

import attrs
import rlp.exceptions
from eth_utils.address import to_checksum_address
from pytempo import AccessListItem, Call, KeychainSignature, Signature, TempoTransaction

from mpp.tempo._internal.hexutil import (
    bytes_to_uint,
    int_to_hex,
    rlp_decode,
    rlp_encode,
    to_bytes,
    to_hex,
)
from mpp.tempo._internal.signature import (
    KeychainEnvelope,
    MultisigSignature,
    extract_address,
    recover_address,
    secp256k1_signature,
)
from mpp.tempo._internal.signature import deserialize as deserialize_signature
from mpp.tempo._internal.signature import to_rpc as signature_to_rpc

SERIALIZED_TYPE: Final = "0x76"
FEE_PAYER_MAGIC: Final = "0x78"

MAX_UINT256: Final = 2**256 - 1
EXPIRING_NONCE_KEY: Final = MAX_UINT256
"""Nonce key that marks an expiring (replay-protected by ``valid_before``) nonce."""

_KEY_TYPES: Final = {0: "secp256k1", 1: "p256", 2: "webAuthn", 3: "multisig"}


class InvalidTransactionError(ValueError):
    pass


class InvalidKeyAuthorizationError(InvalidTransactionError):
    pass


class _RlpPayload(Protocol):
    def as_rlp_payload(self) -> list[Any]: ...


@dataclass(frozen=True, slots=True)
class KeyAuthorizationPayload:
    """A signed key authorization decoded from a transaction, re-encoded unchanged.

    pytempo's :class:`~pytempo.SignedKeyAuthorization` only models secp256k1-signed grants of
    secp256k1, P256 or WebAuthn keys without call scopes or periodic limits; clients may send any
    grant ox accepts.
    """

    rlp: bytes
    """RLP encoding of ``[authorization, signature]``."""

    def as_rlp_payload(self) -> list[Any]:
        return rlp_decode(self.rlp)


def is_tempo_transaction(serialized: str | None) -> bool:
    """Whether a serialized transaction has a ``0x76`` or ``0x78`` envelope prefix."""
    return serialized is not None and serialized.startswith((SERIALIZED_TYPE, FEE_PAYER_MAGIC))


def has_fee_payer(transaction: TempoTransaction) -> bool:
    """Whether the transaction is fee-sponsored (co-signed or awaiting its sponsor)."""
    return transaction.awaiting_fee_payer or transaction.fee_payer_signature is not None


def sender(transaction: TempoTransaction) -> str | None:
    """The checksummed sender (``from``), when known."""
    address = transaction.sender_address
    return to_checksum_address(bytes(address)) if address else None


def fee_token(transaction: TempoTransaction) -> str | None:
    return to_hex(bytes(transaction.fee_token)) if transaction.fee_token else None


def call_target(call: Call) -> str | None:
    return to_hex(bytes(call.to)) if call.to else None


def assert_valid(transaction: TempoTransaction) -> None:
    """ox ``TxEnvelopeTempo.assert`` (pytempo's own ``validate`` runs when it encodes or hashes)."""
    if not transaction.calls:
        raise InvalidTransactionError("Calls list cannot be empty.")
    vb, va = transaction.valid_before, transaction.valid_after
    if vb is not None and va is not None and vb <= va:
        raise InvalidTransactionError(f"validBefore ({vb}) must be greater than validAfter ({va}).")
    if transaction.chain_id <= 0:
        raise InvalidTransactionError(f"Chain ID {transaction.chain_id} is invalid.")
    max_fee, max_priority = transaction.max_fee_per_gas, transaction.max_priority_fee_per_gas
    if max_fee > MAX_UINT256:
        raise InvalidTransactionError("maxFeePerGas cannot be higher than 2^256-1.")
    if max_priority and max_fee and max_priority > max_fee:
        raise InvalidTransactionError("maxPriorityFeePerGas cannot be higher than maxFeePerGas.")


def serialize(transaction: TempoTransaction) -> str:
    """Serializes a transaction as a ``0x76`` envelope (pytempo ``encode``)."""
    assert_valid(transaction)
    if transaction.sender_signature is None:
        # pytempo appends an empty signature item to unsigned transactions (ox omits it).
        raise InvalidTransactionError("Only signed transactions are serialized.")
    if transaction.awaiting_fee_payer and transaction.fee_payer_signature is None:
        # pytempo encodes an empty fee-payer slot here (ox: ``0x00`` and no fee token).
        raise InvalidTransactionError(
            "A sponsored transaction awaiting its fee payer is serialized as a 0x78 envelope."
        )
    try:
        return to_hex(transaction.encode())
    except ValueError as error:
        raise InvalidTransactionError(str(error)) from error


def serialize_for_fee_payer(transaction: TempoTransaction) -> str:
    """Serializes a sender-signed sponsored transaction as a ``0x78`` envelope.

    The fee-payer slot carries the sender address (recovered from the signature when
    ``sender_address`` is unset) and the fee token is stripped: the sponsor picks it.
    """
    assert_valid(transaction)
    signature = transaction.sender_signature
    if signature is None:
        raise InvalidTransactionError("A sender signature is required.")
    address = transaction.sender_address or to_bytes(
        extract_address(signature, sign_payload(transaction), root=True)
    )
    fields: list[Any] = [
        transaction.chain_id,
        transaction.max_priority_fee_per_gas,
        transaction.max_fee_per_gas,
        transaction.gas_limit,
        [call.as_rlp_list() for call in transaction.calls],
        [item.as_rlp_list() for item in transaction.access_list],
        transaction.nonce_key,
        transaction.nonce,
        b"" if transaction.valid_before is None else transaction.valid_before,
        b"" if transaction.valid_after is None else transaction.valid_after,
        b"",
        bytes(address),
        list(transaction.tempo_authorization_list),
    ]
    if transaction.key_authorization is not None:
        fields.append(transaction.key_authorization.as_rlp_payload())
    fields.append(signature.to_bytes())
    return to_hex(bytes([0x78]) + rlp_encode(fields))


def sign_payload(transaction: TempoTransaction) -> bytes:
    """The digest the sender signs (pytempo's sender signing hash)."""
    # pytempo requires ``sender_address`` whenever a fee-payer signature is set, even though the
    # sender hash excludes both; hash the equivalent awaiting form so the sender can be recovered.
    presign = attrs.evolve(
        transaction, awaiting_fee_payer=has_fee_payer(transaction), fee_payer_signature=None
    )
    try:
        return presign.get_signing_hash()
    except ValueError as error:
        raise InvalidTransactionError(str(error)) from error


def fee_payer_sign_payload(transaction: TempoTransaction, *, sender: str) -> bytes:
    """The digest a fee payer signs to sponsor ``sender``'s transaction (pytempo ``0x78`` hash)."""
    assert_valid(transaction)
    try:
        return attrs.evolve(transaction, sender_address=sender).get_signing_hash(for_fee_payer=True)
    except ValueError as error:
        raise InvalidTransactionError(str(error)) from error


def transaction_hash(transaction: TempoTransaction) -> str:
    return to_hex(transaction.hash())


def recover_fee_payer(transaction: TempoTransaction) -> str:
    """Recovers the sponsor address from a co-signed transaction."""
    address = sender(transaction)
    if transaction.fee_payer_signature is None or address is None:
        raise InvalidTransactionError("Transaction has no fee payer signature.")
    return recover_address(
        fee_payer_sign_payload(transaction, sender=address), transaction.fee_payer_signature
    )


def deserialize(serialized: str) -> TempoTransaction:
    """Parses a ``0x76`` or ``0x78`` envelope, recovering the sender from its signature."""
    raw = to_bytes(serialized)
    try:
        items = rlp_decode(raw[1:])
    except rlp.exceptions.DecodingError as error:
        raise InvalidTransactionError(f"Invalid serialized transaction: {error}") from error
    if not isinstance(items, list) or len(items) not in (13, 14, 15):
        raise InvalidTransactionError("Invalid serialized Tempo transaction.")
    (
        chain_id,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas,
        calls,
        access_list,
        nonce_key,
        nonce,
        valid_before,
        valid_after,
        token,
        fee_payer_field,
        authorization_list,
        *tail,
    ) = items
    key_authorization_items = tail[0] if tail and isinstance(tail[0], list) else None
    signature_raw = (
        (tail[1] if len(tail) > 1 else None)
        if key_authorization_items
        else (tail[0] if tail else None)
    )
    if authorization_list:
        # pytempo models authorization-list entries as opaque byte strings, not RLP lists.
        raise InvalidTransactionError("Tempo authorization lists are not supported.")

    awaiting_fee_payer = False
    fee_payer_signature: Signature | None = None
    sender_address: bytes | None = None
    if isinstance(fee_payer_field, list) and len(fee_payer_field) == 3:
        y_parity, r, s = (_scalar(value) for value in fee_payer_field)
        fee_payer_signature = secp256k1_signature(r=r, s=s, y_parity=y_parity)
    elif fee_payer_field == b"\x00":
        awaiting_fee_payer = True
    elif isinstance(fee_payer_field, bytes) and len(fee_payer_field) == 20:
        awaiting_fee_payer, sender_address = True, fee_payer_field
    elif fee_payer_field:
        raise InvalidTransactionError("Invalid fee payer signature.")

    if signature_raw is not None and not isinstance(signature_raw, bytes):
        raise InvalidTransactionError("Invalid transaction signature.")
    try:
        transaction = TempoTransaction(
            chain_id=_scalar(chain_id),
            max_priority_fee_per_gas=_scalar(max_priority_fee_per_gas),
            max_fee_per_gas=_scalar(max_fee_per_gas),
            gas_limit=_scalar(gas),
            calls=tuple(Call(to=to, value=_scalar(value), data=data) for to, value, data in calls),
            access_list=tuple(
                AccessListItem(address=address, storage_keys=tuple(keys))
                for address, keys in access_list
            ),
            nonce_key=_scalar(nonce_key),
            nonce=_scalar(nonce),
            valid_before=_scalar(valid_before) if valid_before else None,
            valid_after=_scalar(valid_after) if valid_after else None,
            fee_token=token or None,
            sender_address=sender_address,
            awaiting_fee_payer=awaiting_fee_payer,
            fee_payer_signature=fee_payer_signature,
        )
        transaction = attrs.evolve(
            transaction,
            sender_signature=deserialize_signature(signature_raw) if signature_raw else None,
            key_authorization=decode_key_authorization(key_authorization_items)
            if key_authorization_items
            else None,
        )
    except (TypeError, ValueError) as error:
        if isinstance(error, InvalidTransactionError):
            raise
        raise InvalidTransactionError(f"Invalid serialized Tempo transaction: {error}") from error
    if transaction.sender_address is None and transaction.sender_signature is not None:
        with contextlib.suppress(ValueError):
            recovered = extract_address(
                transaction.sender_signature, sign_payload(transaction), root=True
            )
            transaction = attrs.evolve(transaction, sender_address=recovered)
    assert_valid(transaction)
    return transaction


def _scalar(value: Any) -> int:
    if not isinstance(value, bytes):
        raise InvalidTransactionError("Expected an RLP scalar.")
    return bytes_to_uint(value)


# -- key authorizations ------------------------------------------------------------------------


def decode_key_authorization(items: Any) -> KeyAuthorizationPayload:
    """Validates ``[authorization, signature]`` RLP items (ox ``KeyAuthorization.fromTuple``)."""
    payload = KeyAuthorizationPayload(rlp_encode(items))
    key_authorization_to_rpc(payload)
    return payload


def key_authorization_to_rpc(authorization: _RlpPayload) -> dict[str, Any]:
    """Formats a signed key authorization as the JSON-RPC object Tempo nodes accept (ox
    ``KeyAuthorization.toRpc``); pytempo's ``to_json`` omits call scopes and periods and differs in
    shape."""
    items = authorization.as_rlp_payload()
    if not isinstance(items, list) or len(items) != 2 or not isinstance(items[0], list):
        raise InvalidKeyAuthorizationError("Invalid key authorization tuple.")
    fields, signature_raw = items
    if len(fields) < 3 or not isinstance(signature_raw, bytes) or not signature_raw:
        raise InvalidKeyAuthorizationError("Invalid key authorization tuple.")
    chain_id, key_type_raw, key_id, *trailing = fields
    key_type = _KEY_TYPES.get(_scalar(key_type_raw))
    if key_type is None:
        raise InvalidKeyAuthorizationError(f"Invalid key type: {to_hex(key_type_raw)}")
    trailing += [b""] * (6 - len(trailing))
    expiry, limits, calls, witness, is_admin, account = trailing[:6]

    signature = deserialize_signature(signature_raw)
    if isinstance(signature, KeychainSignature | KeychainEnvelope):
        raise InvalidKeyAuthorizationError(
            "Signature type `keychain` is invalid for key authorizations."
        )
    if isinstance(signature, MultisigSignature):
        # ox accepts multisig-signed grants; no mpp flow consumes them (mppx rejects them).
        raise InvalidKeyAuthorizationError(
            "Signature type `multisig` is not supported for key authorizations."
        )
    if is_admin not in (b"", b"\x01"):
        raise InvalidKeyAuthorizationError(
            f"Admin marker `{to_hex(is_admin)}` is invalid; expected `0x01` (TIP-1049)."
        )
    if witness != b"" and len(witness) != 32:
        raise InvalidKeyAuthorizationError("Witness must be exactly 32 bytes.")
    if key_type == "multisig" and account == b"":
        raise InvalidKeyAuthorizationError("Multisig key grants require a parent account binding.")

    chain = _scalar(chain_id)
    rpc: dict[str, Any] = {
        "chainId": "0x" if chain == 0 else int_to_hex(chain),
        "expiry": int_to_hex(_scalar(expiry)) if expiry != b"" and _scalar(expiry) else None,
        "keyId": to_hex(key_id),
        "keyType": key_type,
    }
    if isinstance(limits, list) and limits:
        rpc["limits"] = [
            {"token": to_hex(limit[0]), "limit": int_to_hex(_scalar(limit[1]))}
            | ({"period": int_to_hex(_scalar(limit[2]))} if len(limit) > 2 and limit[2] else {})
            for limit in limits
        ]
    rpc["signature"] = signature_to_rpc(signature)
    if isinstance(calls, list):
        rpc["allowedCalls"] = [
            {"target": to_hex(target)}
            | (
                {
                    "selectorRules": [
                        {"selector": to_hex(selector)}
                        | (
                            {"recipients": [to_hex(r) for r in recipients]}
                            if isinstance(recipients, list) and recipients
                            else {}
                        )
                        for selector, recipients in rules
                    ]
                }
                if isinstance(rules, list) and rules
                else {}
            )
            for target, rules in calls
        ]
    if witness != b"":
        rpc["witness"] = to_hex(witness)
    if is_admin == b"\x01":
        rpc["isAdmin"] = True
    if account != b"":
        rpc["account"] = to_hex(account)
    return rpc
