"""Tempo transaction, signature-envelope and key-authorization codecs vs ox 0.14.45 vectors.

Transactions and key authorizations are pytempo models: these vectors pin pytempo's encoding,
signing hashes and signatures to ox byte for byte.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import attrs
import pytest
from eth_account import Account
from pytempo import (
    Call,
    KeyAuthorization,
    KeychainSignature,
    SignatureType,
    TempoTransaction,
)

from mpp.tempo._internal import envelope as tx
from mpp.tempo._internal import signature as sig
from mpp.tempo._internal.account import secp256k1_account
from mpp.tempo._internal.hexutil import keccak256, rlp_decode, rlp_encode, to_bytes, to_hex

V = json.loads((Path(__file__).parent / "fixtures/ox_vectors.json").read_text())
PK1 = "0x" + "11" * 32
PK2 = "0x" + "22" * 32
PATH_USD = "0x20c0000000000000000000000000000000000000"


@pytest.mark.parametrize("name", ["signed", "cosigned", "keychainSigned", "keychainV1"])
def test_roundtrips_ox_serialization(name: str) -> None:
    assert tx.serialize(tx.deserialize(V[name])) == V[name]


def test_unsigned_transactions_are_not_serialized() -> None:
    unsigned = tx.deserialize(V["unsigned"])
    # pytempo encodes an unsigned transaction with an empty signature item that ox omits.
    assert rlp_decode(unsigned.encode()[1:]) == [*rlp_decode(to_bytes(V["unsigned"])[1:]), b""]
    with pytest.raises(tx.InvalidTransactionError, match="signed"):
        tx.serialize(unsigned)


def test_authorization_lists_are_rejected() -> None:
    # pytempo models `tempo_authorization_list` entries as byte strings, so it cannot re-encode
    # ox's `[chainId, address, nonce, signature]` entries.
    with pytest.raises(tx.InvalidTransactionError, match="authorization lists"):
        tx.deserialize(V["withAuthList"])


def test_sign_payload_matches_ox() -> None:
    assert to_hex(tx.sign_payload(tx.deserialize(V["unsigned"]))) == V["signPayload"]


def test_signing_reproduces_ox_signed_envelope() -> None:
    unsigned = tx.deserialize(V["unsigned"])
    signed = secp256k1_account(PK1).sign_transaction(unsigned)
    assert tx.serialize(signed) == V["signed"]
    assert tx.transaction_hash(signed) == V["signedHash"]


def test_deserialize_recovers_sender() -> None:
    expected = Account.from_key(PK1).address
    assert tx.sender(tx.deserialize(V["signed"])) == expected
    assert tx.sender(tx.deserialize(V["cosigned"])) == expected


def test_sponsored_sender_envelope() -> None:
    decoded = tx.deserialize(V["sponsoredSenderSigned"])
    assert decoded.awaiting_fee_payer is True
    assert decoded.fee_payer_signature is None
    assert decoded.fee_token is None
    assert tx.sender(decoded) == Account.from_key(PK1).address
    assert (tx.sender(decoded) or "").lower() == V["sender"].lower()
    assert to_hex(tx.sign_payload(decoded)) == V["sponsoredSignPayload"]
    assert tx.serialize_for_fee_payer(decoded) == V["sponsoredSenderSigned"]


def test_sponsored_client_flow_matches_ox() -> None:
    unsigned = attrs.evolve(tx.deserialize(V["unsigned"]), awaiting_fee_payer=True)
    signed = secp256k1_account(PK1).sign_transaction(unsigned)
    # The client hands the sponsor a 0x78 envelope without a fee token.
    assert tx.serialize_for_fee_payer(signed) == V["sponsoredSenderSigned"]
    # The sponsor signs over its chosen fee token and the sender address.
    payload = tx.fee_payer_sign_payload(signed, sender=tx.sender(signed) or "")
    assert to_hex(payload) == V["feePayerPayload"]
    fee_payer_signature = secp256k1_account(PK2).sign(payload)
    assert isinstance(fee_payer_signature, sig.Signature)
    cosigned = attrs.evolve(signed, fee_payer_signature=fee_payer_signature)
    assert tx.serialize(cosigned) == V["cosigned"]
    assert tx.recover_fee_payer(tx.deserialize(V["cosigned"])) == Account.from_key(PK2).address


def test_awaiting_fee_payer_is_not_serialized_as_0x76() -> None:
    signed = secp256k1_account(PK1).sign_transaction(
        attrs.evolve(tx.deserialize(V["unsigned"]), awaiting_fee_payer=True)
    )
    with pytest.raises(tx.InvalidTransactionError, match="0x78"):
        tx.serialize(signed)


def test_fee_payer_signature_excluded_from_sender_payload() -> None:
    cosigned = tx.deserialize(V["cosigned"])
    assert to_hex(tx.sign_payload(cosigned)) == V["sponsoredSignPayload"]


def test_keychain_v2_signature() -> None:
    decoded = tx.deserialize(V["keychainSigned"])
    envelope = decoded.sender_signature
    assert isinstance(envelope, KeychainSignature)
    assert (tx.sender(decoded) or "").lower() == "0x" + "ef" * 20
    assert to_hex(tx.sign_payload(decoded)) == V["keychainSignPayload"]
    inner_payload = sig.keychain_sign_payload(tx.sign_payload(decoded), "0x" + "ef" * 20)
    assert sig.extract_address(envelope, inner_payload) == Account.from_key(PK2).address
    assert isinstance(decoded.key_authorization, tx.KeyAuthorizationPayload)
    assert to_hex(decoded.key_authorization.rlp) == V["keyAuthSerialized"]


def test_access_key_account_signs_like_ox() -> None:
    unsigned = attrs.evolve(
        tx.deserialize(V["keychainSigned"]), sender_signature=None, sender_address=None
    )
    access_key = secp256k1_account(PK2, access="0x" + "ef" * 20)
    assert access_key.address == "0x" + "ef" * 20
    assert access_key.signer_address == Account.from_key(PK2).address
    assert tx.serialize(access_key.sign_transaction(unsigned)) == V["keychainSigned"]


def test_keychain_v1_signs_the_plain_payload() -> None:
    decoded = tx.deserialize(V["keychainV1"])
    envelope = decoded.sender_signature
    assert isinstance(envelope, sig.KeychainEnvelope)
    assert envelope.version == "v1"
    assert (tx.sender(decoded) or "").lower() == "0x" + "12" * 20
    access_key = secp256k1_account(PK1, access="0x" + "12" * 20, keychain_version="v1")
    unsigned = attrs.evolve(decoded, sender_signature=None, sender_address=None)
    assert tx.serialize(access_key.sign_transaction(unsigned)) == V["keychainV1"]


def test_validation_errors() -> None:
    with pytest.raises(tx.InvalidTransactionError, match="Calls list cannot be empty"):
        tx.serialize(TempoTransaction(chain_id=1, calls=()))
    with pytest.raises(tx.InvalidTransactionError, match="must be greater than validAfter"):
        tx.serialize(
            TempoTransaction(chain_id=1, calls=(Call(to=PATH_USD),), valid_before=1, valid_after=1)
        )
    with pytest.raises(tx.InvalidTransactionError, match="maxPriorityFeePerGas"):
        tx.serialize(
            TempoTransaction(
                chain_id=1,
                calls=(Call(to=PATH_USD),),
                max_fee_per_gas=1,
                max_priority_fee_per_gas=2,
            )
        )
    with pytest.raises(tx.InvalidTransactionError):
        tx.deserialize("0x76c0")


def test_is_tempo_transaction() -> None:
    assert tx.is_tempo_transaction(V["signed"])
    assert tx.is_tempo_transaction(V["sponsoredSenderSigned"])
    assert not tx.is_tempo_transaction("0x02f8")
    assert not tx.is_tempo_transaction(None)


# -- signature envelopes -----------------------------------------------------------------------


def test_p256_envelope_matches_ox() -> None:
    envelope = sig.deserialize(V["p256Envelope"])
    assert isinstance(envelope, sig.P256Signature)
    assert sig.serialize(envelope) == V["p256Envelope"]
    payload = to_bytes(V["p256Payload"])
    assert sig.extract_address(envelope, payload).lower() == V["p256Address"]
    assert sig.verify(envelope, payload=payload, address=V["p256Address"])
    assert not sig.verify(envelope, payload=keccak256(b"other"), address=V["p256Address"])
    assert not sig.verify(envelope, payload=payload, address="0x" + "00" * 20)


def test_p256_prehash_envelope() -> None:
    envelope = sig.deserialize(V["p256Prehash"]["envelope"])
    assert isinstance(envelope, sig.P256Signature)
    assert envelope.prehash
    address = sig.p256_address(envelope.public_key_x, envelope.public_key_y)
    assert sig.verify(envelope, payload=to_bytes(V["p256Prehash"]["payload"]), address=address)


def test_p256_rejects_high_s() -> None:
    envelope = sig.deserialize(V["p256Envelope"])
    assert isinstance(envelope, sig.P256Signature)
    high_s = replace(envelope, s=sig.P256_N - envelope.s)
    assert not sig.verify(high_s, payload=to_bytes(V["p256Payload"]), address=V["p256Address"])


def test_webauthn_envelope_matches_ox() -> None:
    data = V["webauthn"]
    envelope = sig.deserialize(data["envelope"])
    assert isinstance(envelope, sig.WebAuthnSignature)
    assert sig.serialize(envelope) == data["envelope"]
    assert sig.to_rpc(envelope) == V["webauthnRpc"]
    challenge = to_bytes(data["challenge"])
    assert sig.extract_address(envelope, challenge).lower() == data["address"]
    assert sig.verify(envelope, payload=challenge, address=data["address"])
    assert not sig.verify(envelope, payload=keccak256(b"other"), address=data["address"])


def test_magic_suffix_is_stripped() -> None:
    envelope = sig.deserialize(V["p256Envelope"])
    assert sig.deserialize(sig.serialize(envelope, magic=True)) == envelope


def test_unknown_and_multisig_envelopes_are_rejected() -> None:
    with pytest.raises(sig.InvalidSignatureEnvelopeError, match="Unknown signature type"):
        sig.deserialize("0x09" + "00" * 10)
    with pytest.raises(sig.InvalidSignatureEnvelopeError, match="multisig"):
        sig.deserialize("0x05c0")
    with pytest.raises(sig.InvalidSignatureEnvelopeError, match="P256"):
        sig.deserialize("0x01" + "00" * 10)


def test_secp256k1_v_values() -> None:
    raw = to_bytes(V["signed"])[-65:]
    for v, parity in ((0, 0), (1, 1), (27, 0), (28, 1), (37, 0), (38, 1)):
        parsed = sig.parse_secp256k1(raw[:64] + bytes([v]))
        assert sig.y_parity(parsed) == parity
    assert sig.parse_secp256k1(raw).to_bytes()[-1] in (27, 28)


# -- key authorizations ------------------------------------------------------------------------


def test_key_authorization_matches_ox() -> None:
    # Call scopes, periodic limits and a P256 key: pytempo cannot model this grant, so
    # transactions carry it through unchanged.
    decoded = tx.decode_key_authorization(rlp_decode(to_bytes(V["keyAuthSerialized"])))
    assert to_hex(rlp_encode(decoded.as_rlp_payload())) == V["keyAuthSerialized"]
    assert to_hex(keccak256(rlp_encode(decoded.as_rlp_payload()[0]))) == V["keyAuthPayload"]
    expected = V["keyAuthRpc"]
    # ox keeps the caller's checksum casing; decoded addresses are lowercase.
    expected["allowedCalls"][0]["selectorRules"][0]["recipients"] = [
        r.lower() for r in expected["allowedCalls"][0]["selectorRules"][0]["recipients"]
    ]
    assert tx.key_authorization_to_rpc(decoded) == expected


def test_key_authorization_simple_payload() -> None:
    authorization = KeyAuthorization(
        key_id="0x" + "ab" * 20, chain_id=4217, key_type=SignatureType.SECP256K1
    )
    assert to_hex(authorization.signature_hash()) == V["keyAuthSimplePayload"]


@pytest.mark.parametrize("index", [0, 2])
def test_key_authorization_variants_match_ox(index: int) -> None:
    expected = V["keyAuths"][index]
    (items,) = rlp_decode(to_bytes(expected["serialized"]))
    authorization = KeyAuthorization.from_rlp(items)
    assert to_hex(rlp_encode([authorization.as_rlp_payload()])) == expected["serialized"]
    assert to_hex(authorization.signature_hash()) == expected["payload"]


@pytest.mark.parametrize("index", [1, 3])
def test_key_authorization_variants_pytempo_cannot_model(index: int) -> None:
    # 1: an explicitly empty call-scope list; 3: a multisig key.
    (items,) = rlp_decode(to_bytes(V["keyAuths"][index]["serialized"]))
    with pytest.raises(ValueError):  # noqa: PT011
        KeyAuthorization.from_rlp(items)


def test_key_authorization_validation() -> None:
    signature = sig.secp256k1_signature(r=1, s=1, y_parity=0).to_bytes()
    key = to_bytes(PATH_USD)
    with pytest.raises(tx.InvalidKeyAuthorizationError, match="parent account binding"):
        tx.decode_key_authorization([[b"\x01", b"\x03", key], signature])
    with pytest.raises(tx.InvalidKeyAuthorizationError, match="exactly 32 bytes"):
        tx.decode_key_authorization([[b"\x01", b"\x01", key, b"", b"", b"", b"\x12"], signature])
    keychain = b"\x04" + key + signature
    with pytest.raises(tx.InvalidKeyAuthorizationError, match="keychain"):
        tx.decode_key_authorization([[b"\x01", b"\x01", key], keychain])
    with pytest.raises(tx.InvalidKeyAuthorizationError, match="Admin marker"):
        tx.decode_key_authorization([[b"\x01", b"", key, b"", b"", b"", b"", b"\x02"], signature])


def test_access_key_authorization_binds_parent_account() -> None:
    access_key = secp256k1_account(PK2, access="0x" + "ef" * 20)
    signed = access_key.sign_key_authorization(
        KeyAuthorization(key_id="0x" + "ab" * 20, chain_id=4217)
    )
    assert signed.authorization.account == bytes.fromhex("ef" * 20)
    assert signed.recover_signer() == access_key.signer_address
