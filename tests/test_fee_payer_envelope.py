"""Tests for fee payer envelope encoding/decoding (0x78 wire format)."""

import time

import attrs
import pytest
import rlp
from pytempo import Call, TempoTransaction
from pytempo.models import Signature

from mpp.methods.tempo.fee_payer_envelope import (
    decode_fee_payer_envelope,
    encode_fee_payer_envelope,
)

TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CURRENCY = "0x20c0000000000000000000000000000000000000"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"


def _make_signed_tx(
    chain_id: int = 42431,
    fee_token: str | None = None,
    valid_before: int | None = 9999999999,
    valid_after: int | None = None,
) -> TempoTransaction:
    """Create and sign a fee-payer-awaiting transaction."""
    selector = "a9059cbb"
    to_padded = RECIPIENT[2:].lower().zfill(64)
    amount_padded = hex(1000000)[2:].zfill(64)
    transfer_data = f"0x{selector}{to_padded}{amount_padded}"

    tx = TempoTransaction.create(
        chain_id=chain_id,
        gas_limit=100000,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=1,
        nonce=0,
        nonce_key=(1 << 256) - 1,
        fee_token=fee_token,
        awaiting_fee_payer=True,
        valid_before=valid_before,
        valid_after=valid_after,
        calls=(Call.create(to=CURRENCY, value=0, data=transfer_data),),
    )
    return tx.sign(TEST_PRIVATE_KEY)


class TestEncodeFeePayerEnvelope:
    """Tests for encode_fee_payer_envelope."""

    def test_prefix_byte_is_0x78(self) -> None:
        """Encoded envelope must start with 0x78."""
        signed = _make_signed_tx()
        encoded = encode_fee_payer_envelope(signed)
        assert encoded[0] == 0x78

    def test_rlp_decodable(self) -> None:
        """The payload after the prefix must be valid RLP."""
        signed = _make_signed_tx()
        encoded = encode_fee_payer_envelope(signed)
        decoded = rlp.decode(encoded[1:])
        assert isinstance(decoded, list)
        assert len(decoded) >= 14

    def test_sender_address_at_index_11(self) -> None:
        """Sender address must be at field index 11."""
        signed = _make_signed_tx()
        encoded = encode_fee_payer_envelope(signed)
        decoded = rlp.decode(encoded[1:])
        sender_addr = decoded[11]
        assert len(sender_addr) == 20
        assert sender_addr == bytes(signed.sender_address)  # type: ignore[arg-type]

    def test_sender_signature_is_last_field(self) -> None:
        """Sender signature (65 bytes r||s||v) must be the last field."""
        signed = _make_signed_tx()
        encoded = encode_fee_payer_envelope(signed)
        decoded = rlp.decode(encoded[1:])
        sig = decoded[-1]
        assert len(sig) == 65
        assert sig == signed.sender_signature.to_bytes()  # type: ignore[union-attr]

    def test_chain_id_preserved(self) -> None:
        """Chain ID must be correctly encoded at index 0."""
        signed = _make_signed_tx(chain_id=42431)
        encoded = encode_fee_payer_envelope(signed)
        decoded = rlp.decode(encoded[1:])
        chain_id = int.from_bytes(decoded[0], "big") if decoded[0] else 0
        assert chain_id == 42431

    def test_calls_preserved(self) -> None:
        """Calls list must be correctly encoded at index 4."""
        signed = _make_signed_tx()
        encoded = encode_fee_payer_envelope(signed)
        decoded = rlp.decode(encoded[1:])
        calls = decoded[4]
        assert isinstance(calls, list)
        assert len(calls) == 1
        # First call target should be the currency address
        call_to = "0x" + calls[0][0].hex()
        assert call_to.lower() == CURRENCY.lower()

    def test_optional_fields_empty_when_none(self) -> None:
        """valid_after and fee_token should encode as b'' when None."""
        signed = _make_signed_tx(valid_after=None, fee_token=None)
        encoded = encode_fee_payer_envelope(signed)
        decoded = rlp.decode(encoded[1:])
        # valid_after at index 9
        assert decoded[9] == b""
        # fee_token at index 10
        assert decoded[10] == b""

    def test_valid_before_encoded(self) -> None:
        """valid_before value should be correctly encoded at index 8."""
        signed = _make_signed_tx(valid_before=9999999999)
        encoded = encode_fee_payer_envelope(signed)
        decoded = rlp.decode(encoded[1:])
        vb = int.from_bytes(decoded[8], "big") if decoded[8] else 0
        assert vb == 9999999999

    def test_differs_from_0x76_encode(self) -> None:
        """0x78 envelope must differ from standard 0x76 encode."""
        signed = _make_signed_tx()
        envelope = encode_fee_payer_envelope(signed)

        # For 0x76 we need a fee_payer_signature
        tx_76 = attrs.evolve(signed, fee_payer_signature=Signature(r=1, s=1, v=27))
        encoded_76 = tx_76.encode()

        assert envelope[0] == 0x78
        assert encoded_76[0] == 0x76
        assert envelope != encoded_76


class TestDecodeFeePayerEnvelope:
    """Tests for decode_fee_payer_envelope."""

    def test_roundtrip(self) -> None:
        """encode then decode should preserve sender address and signature."""
        signed = _make_signed_tx()
        encoded = encode_fee_payer_envelope(signed)
        decoded, sender_addr, sender_sig, key_auth = decode_fee_payer_envelope(encoded)

        assert sender_addr == bytes(signed.sender_address)  # type: ignore[arg-type]
        assert sender_sig == signed.sender_signature.to_bytes()  # type: ignore[union-attr]
        assert key_auth is None

    def test_roundtrip_fields(self) -> None:
        """Decoded RLP fields should match original transaction fields."""
        signed = _make_signed_tx(chain_id=42431)
        encoded = encode_fee_payer_envelope(signed)
        decoded, _, _, _ = decode_fee_payer_envelope(encoded)

        def _int(b: bytes) -> int:
            return int.from_bytes(b, "big") if b else 0

        assert _int(decoded[0]) == 42431
        assert _int(decoded[1]) == signed.max_priority_fee_per_gas
        assert _int(decoded[2]) == signed.max_fee_per_gas
        assert _int(decoded[3]) == signed.gas_limit
        assert _int(decoded[6]) == signed.nonce_key
        assert _int(decoded[7]) == signed.nonce
        assert _int(decoded[8]) == 9999999999  # valid_before

    def test_rejects_wrong_prefix(self) -> None:
        """Should reject data not starting with 0x78."""
        with pytest.raises(ValueError, match="expected 0x78 prefix"):
            decode_fee_payer_envelope(b"\x76" + b"\x00" * 20)

    def test_rejects_0x76_prefix(self) -> None:
        """Should reject a standard 0x76 transaction."""
        signed = _make_signed_tx()
        tx_76 = attrs.evolve(signed, fee_payer_signature=Signature(r=1, s=1, v=27))
        encoded_76 = tx_76.encode()
        with pytest.raises(ValueError, match="expected 0x78 prefix"):
            decode_fee_payer_envelope(encoded_76)

    def test_rejects_empty_data(self) -> None:
        """Should reject empty input."""
        with pytest.raises(ValueError, match="expected 0x78 prefix"):
            decode_fee_payer_envelope(b"")

    def test_rejects_too_short_rlp(self) -> None:
        """Should reject RLP with too few fields."""
        # 0x78 + RLP of a short list
        short = bytes([0x78]) + bytes(rlp.encode([b"", b"", b""]))
        with pytest.raises(ValueError, match="Malformed"):
            decode_fee_payer_envelope(short)

    def test_rejects_invalid_rlp(self) -> None:
        """Malformed RLP raises ValueError, not rlp.DecodingError."""
        with pytest.raises(ValueError, match="Malformed fee payer envelope"):
            decode_fee_payer_envelope(bytes([0x78, 0xC5, 0x01]))

    def test_rejects_list_fee_fields(self) -> None:
        """A list in a scalar slot such as max_fee_per_gas raises ValueError."""
        fields: list = [b""] * 14
        fields[2] = [b"\x01"]
        with pytest.raises(ValueError, match="Malformed fee payer envelope"):
            decode_fee_payer_envelope(bytes([0x78]) + rlp.encode(fields))

    def test_rejects_deeply_nested_rlp(self) -> None:
        """RLP nested past the recursion limit raises ValueError, not RecursionError."""
        # rlp.encode itself recurses, so build the nested lists by hand.
        nested = b"\xc0"
        for _ in range(5_000):
            size = len(nested)
            if size <= 55:
                nested = bytes([0xC0 + size]) + nested
            else:
                length = size.to_bytes((size.bit_length() + 7) // 8, "big")
                nested = bytes([0xF7 + len(length)]) + length + nested
        with pytest.raises(ValueError, match="Malformed fee payer envelope"):
            decode_fee_payer_envelope(bytes([0x78]) + nested)

    def test_rejects_list_sender_fields(self) -> None:
        """A list where the sender address or signature belongs raises ValueError."""
        fields: list = [b""] * 14
        fields[11] = [b"\x01"]
        with pytest.raises(ValueError, match="Malformed fee payer envelope"):
            decode_fee_payer_envelope(bytes([0x78]) + rlp.encode(fields))


class TestEncoderDecoderIntegration:
    """Integration tests: encode → decode → cosign roundtrip."""

    def test_cosign_roundtrip(self) -> None:
        """Server should be able to cosign a client-produced 0x78 envelope."""
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        signed = _make_signed_tx(valid_before=int(time.time()) + 300)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer_key = "0x" + "ab" * 32
        fee_payer = TempoAccount.from_key(fee_payer_key)
        intent = ChargeIntent(rpc_url="https://rpc.test", fee_payer=fee_payer)

        result, _ = intent._cosign_as_fee_payer(envelope_hex, CURRENCY)
        assert result.startswith("0x76")

        # The co-signed tx should be valid RLP with 0x76 prefix
        result_bytes = bytes.fromhex(result[2:])
        assert result_bytes[0] == 0x76
        decoded = rlp.decode(result_bytes[1:])
        # Should have fee_payer_signature as a list [v, r, s] (not b"\x00")
        fee_payer_sig = decoded[11]
        assert isinstance(fee_payer_sig, list)
        assert len(fee_payer_sig) == 3

    def test_cosign_rejects_tampered_sender_address(self) -> None:
        """Server should reject an envelope where sender_address doesn't match the signature."""
        from mpp.errors import VerificationError
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        signed = _make_signed_tx(valid_before=int(time.time()) + 300)
        encoded = encode_fee_payer_envelope(signed)

        # Tamper with sender_address (index 11) by replacing it
        decoded_fields = rlp.decode(encoded[1:])
        # Replace sender address with a different address
        decoded_fields[11] = b"\xde\xad" + b"\x00" * 18
        tampered = bytes([0x78]) + bytes(rlp.encode(decoded_fields))
        tampered_hex = "0x" + tampered.hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test", fee_payer=fee_payer)

        with pytest.raises(VerificationError, match="Sender address does not match"):
            intent._cosign_as_fee_payer(tampered_hex, CURRENCY)

    def test_cosign_rejects_fee_token_in_envelope(self) -> None:
        """Server should reject an envelope that includes fee_token (server sets it)."""
        from mpp.errors import VerificationError
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        signed = _make_signed_tx(fee_token=CURRENCY)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test", fee_payer=fee_payer)

        with pytest.raises(VerificationError, match="must not include fee_token"):
            intent._cosign_as_fee_payer(envelope_hex, CURRENCY)

    def test_cosign_rejects_non_expiring_nonce_key(self) -> None:
        """Server should reject an envelope with a non-expiring nonce key."""
        from mpp.errors import VerificationError
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        signed = _make_signed_tx()
        encoded = encode_fee_payer_envelope(signed)

        # Tamper nonce_key (index 6) to a non-MAX value
        decoded_fields = rlp.decode(encoded[1:])
        decoded_fields[6] = (42).to_bytes(1, "big")
        tampered = bytes([0x78]) + bytes(rlp.encode(decoded_fields))
        tampered_hex = "0x" + tampered.hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test", fee_payer=fee_payer)

        with pytest.raises(VerificationError, match="expiring nonce key"):
            intent._cosign_as_fee_payer(tampered_hex, CURRENCY)

    def test_cosign_rejects_missing_valid_before(self) -> None:
        """Server should reject an envelope without valid_before."""
        from mpp.errors import VerificationError
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        signed = _make_signed_tx(valid_before=None)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test", fee_payer=fee_payer)

        with pytest.raises(VerificationError, match="must include valid_before"):
            intent._cosign_as_fee_payer(envelope_hex, CURRENCY)

    def test_cosign_rejects_expired_valid_before(self) -> None:
        """Server should reject an envelope with valid_before in the past."""
        from mpp.errors import VerificationError
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        signed = _make_signed_tx(valid_before=1)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test", fee_payer=fee_payer)

        with pytest.raises(VerificationError, match="expired"):
            intent._cosign_as_fee_payer(envelope_hex, CURRENCY)

    def test_encode_decode_with_fee_token(self) -> None:
        """Should correctly roundtrip when fee_token is set."""
        signed = _make_signed_tx(fee_token=CURRENCY)
        encoded = encode_fee_payer_envelope(signed)
        decoded, sender_addr, sender_sig, key_auth = decode_fee_payer_envelope(encoded)

        # fee_token at index 10 should be 20 bytes
        assert len(decoded[10]) == 20
        assert ("0x" + decoded[10].hex()).lower() == CURRENCY.lower()
        assert sender_addr == bytes(signed.sender_address)  # type: ignore[arg-type]
        assert key_auth is None


# Full T6 (TIP-1049) keyAuthorization payload:
#   [chain_id, key_type, key_id, expiry, limits, allowed_calls, witness, is_admin, account]
# Values are hand-encoded byte strings; only byte-exact round-tripping matters here.
_T6_KEY_AUTH_PAYLOAD = [
    [
        (42431).to_bytes(2, "big"),  # chain_id
        b"\x00",  # key_type
        bytes.fromhex("11" * 20),  # key_id
        (9999999999).to_bytes(5, "big"),  # expiry
        [],  # limits
        [[bytes.fromhex("22" * 20), b"\xa9\x05\x9c\xbb"]],  # allowed_calls (TIP-1011)
        b"",  # witness (TIP-1053)
        b"\x01",  # is_admin (TIP-1049)
        bytes.fromhex("33" * 20),  # account (TIP-1049)
    ],
    bytes.fromhex("44" * 65),  # 65-byte root signature over the authorization
]


def _sign_tx_with_key_auth(key_auth_payload: list) -> TempoTransaction:
    """Sign a fee-payer-awaiting tx whose sender signature commits to ``key_auth_payload``."""

    class _Stub:
        def as_rlp_payload(self) -> list:
            return key_auth_payload

    selector = "a9059cbb"
    to_padded = RECIPIENT[2:].lower().zfill(64)
    amount_padded = hex(1000000)[2:].zfill(64)
    transfer_data = f"0x{selector}{to_padded}{amount_padded}"

    tx = TempoTransaction.create(
        chain_id=42431,
        gas_limit=100000,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=1,
        nonce=0,
        nonce_key=(1 << 256) - 1,
        awaiting_fee_payer=True,
        valid_before=int(time.time()) + 300,
        calls=(Call.create(to=CURRENCY, value=0, data=transfer_data),),
        key_authorization=_Stub(),  # type: ignore[arg-type]
    )
    return tx.sign(TEST_PRIVATE_KEY)


class TestKeyAuthorizationRoundtrip:
    """The decoded keyAuthorization must preserve every signed field (TIP-1049 T6)."""

    def test_cosign_rejects_malformed_key_authorization(self) -> None:
        """A key authorization the node cannot read is refused before signing."""
        from unittest.mock import patch

        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent, VerificationError

        # Its allowed_calls scope lacks a selector-rule list.
        signed = _sign_tx_with_key_auth(_T6_KEY_AUTH_PAYLOAD)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()
        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test", fee_payer=fee_payer)

        with patch.object(TempoTransaction, "sign") as sign:
            with pytest.raises(VerificationError, match="malformed keyAuthorization"):
                intent._cosign_as_fee_payer(envelope_hex, CURRENCY)
            sign.assert_not_called()

    def test_cosign_carries_key_authorization(self) -> None:
        """Like mppx, a key authorization is co-signed and simulated, not refused."""
        from pytempo.keychain import KeyAuthorization

        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        root = TempoAccount.from_key(TEST_PRIVATE_KEY)
        access = TempoAccount.from_key("0x" + "cd" * 32)
        auth = KeyAuthorization(key_id=access.address, chain_id=42431).sign(TEST_PRIVATE_KEY)
        tx = attrs.evolve(
            _make_signed_tx(valid_before=int(time.time()) + 300), key_authorization=auth
        )
        signed = tx.sign_access_key(access.private_key, root.address)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()
        intent = ChargeIntent(
            rpc_url="https://rpc.test", fee_payer=TempoAccount.from_key("0x" + "ab" * 32)
        )

        raw, simulate_payload = intent._cosign_as_fee_payer(envelope_hex, CURRENCY)

        fields = rlp.decode(bytes.fromhex(raw[4:]))
        assert len(fields) == 15
        assert rlp.encode(fields[13]) == auth.rlp_encode()
        assert signed.sender_signature is not None
        assert fields[14] == signed.sender_signature.to_bytes()
        sender_call, sponsored = simulate_payload
        assert sender_call["from"].lower() == sponsored["from"].lower() == root.address.lower()
        assert "keyAuthorization" not in sender_call
        assert sponsored["keyAuthorization"]["keyId"] == access.address.lower()
        assert sponsored["keyAuthorization"]["signature"]["type"] == "secp256k1"

    def test_decode_preserves_payload(self) -> None:
        """The decode wrapper re-encodes the original keyAuthorization verbatim."""
        signed = _sign_tx_with_key_auth(_T6_KEY_AUTH_PAYLOAD)
        encoded = encode_fee_payer_envelope(signed)
        _, _, _, key_auth = decode_fee_payer_envelope(encoded)

        assert key_auth is not None
        assert key_auth.as_rlp_payload() == _T6_KEY_AUTH_PAYLOAD

    def test_encode_accepts_object_key_authorization(self) -> None:
        """encode must read ``as_rlp_payload()``, not rlp.decode() an object."""
        signed = _sign_tx_with_key_auth(_T6_KEY_AUTH_PAYLOAD)
        encoded = encode_fee_payer_envelope(signed)

        decoded = rlp.decode(encoded[1:])
        assert len(decoded) == 15
        assert decoded[13] == _T6_KEY_AUTH_PAYLOAD

    def test_decode_preserves_non_secp256k1_key_auth_signature(self) -> None:
        """The root's authorization signature may be a P256/WebAuthn envelope
        (not a 65-byte secp256k1 sig); it must still round-trip verbatim."""
        p256_payload = [
            list(_T6_KEY_AUTH_PAYLOAD[0]),
            b"\x01" + b"\x55" * 129,  # P256 envelope: 0x01 || 129 bytes
        ]
        signed = _sign_tx_with_key_auth(p256_payload)
        encoded = encode_fee_payer_envelope(signed)
        _, _, _, key_auth = decode_fee_payer_envelope(encoded)

        assert key_auth is not None
        assert key_auth.as_rlp_payload() == p256_payload

    def test_decode_rejects_malformed_key_authorization(self) -> None:
        """A keyAuthorization with an empty signature is rejected."""
        from mpp.methods.tempo.fee_payer_envelope import _decode_signed_key_authorization

        with pytest.raises(ValueError, match="Malformed key_authorization signature"):
            _decode_signed_key_authorization([[b"\x00"], b""])


class TestTempoAuthorizationListRoundtrip:
    """tempo_authorization_list is part of the signing hash and must survive cosign."""

    def test_cosign_rejects_authorization_list(self) -> None:
        """mppx refuses an authorizationList as an unsupported sponsored field."""
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        auth_list = (b"\x77" * 20, b"\x88" * 32)

        selector = "a9059cbb"
        to_padded = RECIPIENT[2:].lower().zfill(64)
        amount_padded = hex(1000000)[2:].zfill(64)
        transfer_data = f"0x{selector}{to_padded}{amount_padded}"
        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=100000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=1,
            nonce=0,
            nonce_key=(1 << 256) - 1,
            awaiting_fee_payer=True,
            valid_before=int(time.time()) + 300,
            calls=(Call.create(to=CURRENCY, value=0, data=transfer_data),),
            tempo_authorization_list=auth_list,
        )
        signed = tx.sign(TEST_PRIVATE_KEY)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test", fee_payer=fee_payer)

        from unittest.mock import patch

        from mpp.errors import VerificationError

        with patch.object(TempoTransaction, "sign") as sign:
            with pytest.raises(VerificationError, match="unsupported fields: authorizationList"):
                intent._cosign_as_fee_payer(envelope_hex, CURRENCY)
            sign.assert_not_called()

    def test_cosign_plain_tx_still_builds_simulate_payload(self) -> None:
        """A tx without authorization fields keeps the pre-broadcast simulation."""
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        signed = _make_signed_tx(valid_before=int(time.time()) + 300)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test", fee_payer=fee_payer)

        result, simulate_payload = intent._cosign_as_fee_payer(envelope_hex, CURRENCY)
        assert result.startswith("0x76")
        assert simulate_payload is not None
        assert [r["type"] for r in simulate_payload] == ["0x76", "0x76"]


_P256_PUBLIC_KEY = bytes.fromhex("cc" * 32 + "dd" * 32)


def _p256_signature() -> bytes:
    return b"\x01" + bytes.fromhex("aa" * 32 + "0b" * 32) + _P256_PUBLIC_KEY + b"\x00"


def _webauthn_signature() -> bytes:
    metadata = bytes(37) + b'{"type":"webauthn.get"}'
    return b"\x02" + metadata + bytes.fromhex("aa" * 32 + "0b" * 32) + _P256_PUBLIC_KEY


def _envelope_with_signature(signature: bytes, sender: str) -> str:
    """A 0x78 envelope from ``sender`` carrying ``signature`` unchanged."""
    from mpp.methods.tempo._fee_payer import _RawSenderSignature

    tx = attrs.evolve(
        _make_signed_tx(valid_before=int(time.time()) + 300),
        sender_address=sender,
        sender_signature=_RawSenderSignature(signature),
    )
    return "0x" + encode_fee_payer_envelope(tx).hex()


class TestNonSecp256k1SenderSignatures:
    """Like mppx, keychain, P256 and WebAuthn senders are co-signed; the chain verifies them."""

    @staticmethod
    def _intent():
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo.intents import ChargeIntent

        return ChargeIntent(
            rpc_url="https://rpc.test", fee_payer=TempoAccount.from_key("0x" + "ab" * 32)
        )

    def test_cosigns_keychain_signature(self) -> None:
        from mpp.methods.tempo import TempoAccount

        root = "0x" + "77" * 20
        access = TempoAccount.from_key("0x" + "cd" * 32)
        unsigned = attrs.evolve(
            _make_signed_tx(valid_before=int(time.time()) + 300), sender_signature=None
        )
        signed = unsigned.sign_access_key(access.private_key, root)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        raw, simulate_payload = self._intent()._cosign_as_fee_payer(envelope_hex, CURRENCY)

        assert signed.sender_signature is not None
        assert rlp.decode(bytes.fromhex(raw[4:]))[-1] == signed.sender_signature.to_bytes()
        assert all(request["from"].lower() == root for request in simulate_payload)

    @pytest.mark.parametrize("signature", [_p256_signature(), _webauthn_signature()])
    def test_cosigns_p256_and_webauthn_signatures(self, signature: bytes) -> None:
        from eth_hash.auto import keccak

        sender = "0x" + keccak(_P256_PUBLIC_KEY)[-20:].hex()
        raw, simulate_payload = self._intent()._cosign_as_fee_payer(
            _envelope_with_signature(signature, sender), CURRENCY
        )

        fields = rlp.decode(bytes.fromhex(raw[4:]))
        assert fields[-1] == signature
        assert fields[11] != b""  # the fee payer signature
        assert all(request["from"].lower() == sender for request in simulate_payload)

    def test_rejects_signature_naming_another_sender(self) -> None:
        from mpp.errors import VerificationError

        keychain = b"\x04" + b"\x11" * 20 + b"\x22" * 65
        with pytest.raises(VerificationError, match="does not match recovered signer"):
            self._intent()._cosign_as_fee_payer(
                _envelope_with_signature(keychain, "0x" + "33" * 20), CURRENCY
            )

    @pytest.mark.parametrize(
        "signature",
        [
            _p256_signature()[:-1],
            b"\x04" + b"\x11" * 20 + b"\x22" * 64,
            b"\x02" + b"\x22" * 127,
            b"\x09" + b"\x22" * 129,
        ],
        ids=["short-p256", "short-keychain-inner", "short-webauthn", "unknown-type"],
    )
    def test_rejects_malformed_signature_envelopes(self, signature: bytes) -> None:
        from mpp.errors import VerificationError

        with pytest.raises(VerificationError, match="Invalid sender signature"):
            self._intent()._cosign_as_fee_payer(
                _envelope_with_signature(signature, "0x" + "11" * 20), CURRENCY
            )


# Signed keyAuthorization RLP and the JSON ox 0.14.45 renders for it with
# ``KeyAuthorization.toRpc(KeyAuthorization.fromTuple(...))`` (mppx's simulation request).
_KEY_AUTHORIZATION_RPC_FIXTURES = [
    (
        "f8eef8a982a5bf8094111111111111111111111111111111111111111184773593fff6da9420c0"
        "000000000000000000000000000000000000843b9aca00da9420c000000000000000000000000000"
        "00000000000583015180f852f8399420c0000000000000000000000000000000000000e3db849577"
        "7d59d5942222222222222222222222222222222222222222c684a9059cbbc0d69422222222222222"
        "22222222222222222222222222c0b841" + "aa" * 32 + "0b" * 32 + "1c",
        {
            "allowedCalls": [
                {
                    "selectorRules": [
                        {"recipients": ["0x" + "22" * 20], "selector": "0x95777d59"},
                        {"selector": "0xa9059cbb"},
                    ],
                    "target": "0x20c0000000000000000000000000000000000000",
                },
                {"target": "0x" + "22" * 20},
            ],
            "chainId": "0xa5bf",
            "expiry": "0x773593ff",
            "keyId": "0x" + "11" * 20,
            "keyType": "secp256k1",
            "limits": [
                {"limit": "0x3b9aca00", "token": "0x20c0000000000000000000000000000000000000"},
                {
                    "limit": "0x5",
                    "period": "0x15180",
                    "token": "0x20c0000000000000000000000000000000000000",
                },
            ],
            "signature": {
                "r": "0x" + "aa" * 32,
                "s": "0x" + "0b" * 32,
                "type": "secp256k1",
                "yParity": "0x1",
            },
        },
    ),
    (
        "f8d9f85382107901941111111111111111111111111111111111111111808080a0" + "33" * 32 + "80"
        "942222222222222222222222222222222222222222b88201"
        + "aa" * 32
        + "0b" * 32
        + "cc" * 32
        + "dd" * 32
        + "01",
        {
            "account": "0x" + "22" * 20,
            "chainId": "0x1079",
            "expiry": None,
            "keyId": "0x" + "11" * 20,
            "keyType": "p256",
            "signature": {
                "preHash": True,
                "pubKeyX": "0x" + "cc" * 32,
                "pubKeyY": "0x" + "dd" * 32,
                "r": "0x" + "aa" * 32,
                "s": "0x" + "0b" * 32,
                "type": "p256",
            },
            "witness": "0x" + "33" * 32,
        },
    ),
    (
        "f8f0f0800294111111111111111111111111111111111111111180d7d69420c00000000000000000"
        "0000000000000000000007b8bd02" + "00" * 37 + "7b2274797065223a22776562617574686e2e"
        "676574227d" + "aa" * 32 + "0b" * 32 + "cc" * 32 + "dd" * 32,
        {
            "chainId": "0x",
            "expiry": None,
            "keyId": "0x" + "11" * 20,
            "keyType": "webAuthn",
            "limits": [{"limit": "0x7", "token": "0x20c0000000000000000000000000000000000000"}],
            "signature": {
                "pubKeyX": "0x" + "cc" * 32,
                "pubKeyY": "0x" + "dd" * 32,
                "r": "0x" + "aa" * 32,
                "s": "0x" + "0b" * 32,
                "type": "webAuthn",
                "webauthnData": "0x" + "00" * 37 + "7b2274797065223a22776562617574686e2e676574227d",
            },
        },
    ),
]


@pytest.mark.parametrize(
    ("encoded", "expected"), _KEY_AUTHORIZATION_RPC_FIXTURES, ids=["secp256k1", "p256", "webauthn"]
)
def test_key_authorization_rpc_matches_ox(encoded: str, expected: dict[str, object]) -> None:
    from mpp.methods.tempo._fee_payer import key_authorization_rpc

    assert key_authorization_rpc(rlp.decode(bytes.fromhex(encoded))) == expected


def test_key_authorization_rpc_keeps_an_empty_limits_list() -> None:
    """An empty list means no spending; the broadcast transaction keeps it, so does the call."""
    from mpp.methods.tempo._fee_payer import key_authorization_rpc

    payload = [[b"\x01", b"", b"\x11" * 20, b"", []], b"\x22" * 64 + b"\x1b"]
    assert key_authorization_rpc(payload)["limits"] == []
