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


class TestEncoderDecoderIntegration:
    """Integration tests: encode → decode → cosign roundtrip."""

    def test_cosign_roundtrip(self) -> None:
        """Server should be able to cosign a client-produced 0x78 envelope."""
        from mpp.methods.tempo import TempoAccount, tempo
        from mpp.methods.tempo.intents import ChargeIntent

        signed = _make_signed_tx(valid_before=int(time.time()) + 300)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer_key = "0x" + "ab" * 32
        fee_payer = TempoAccount.from_key(fee_payer_key)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        result = intent._cosign_as_fee_payer(envelope_hex, CURRENCY)
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
        from mpp.methods.tempo import TempoAccount, tempo
        from mpp.methods.tempo.intents import ChargeIntent
        from mpp.server.intent import VerificationError

        signed = _make_signed_tx(valid_before=int(time.time()) + 300)
        encoded = encode_fee_payer_envelope(signed)

        # Tamper with sender_address (index 11) by replacing it
        decoded_fields = rlp.decode(encoded[1:])
        # Replace sender address with a different address
        decoded_fields[11] = b"\xde\xad" + b"\x00" * 18
        tampered = bytes([0x78]) + bytes(rlp.encode(decoded_fields))
        tampered_hex = "0x" + tampered.hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        with pytest.raises(VerificationError, match="Sender address does not match"):
            intent._cosign_as_fee_payer(tampered_hex, CURRENCY)

    def test_cosign_rejects_fee_token_in_envelope(self) -> None:
        """Server should reject an envelope that includes fee_token (server sets it)."""
        from mpp.methods.tempo import TempoAccount, tempo
        from mpp.methods.tempo.intents import ChargeIntent
        from mpp.server.intent import VerificationError

        signed = _make_signed_tx(fee_token=CURRENCY)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        with pytest.raises(VerificationError, match="must not include fee_token"):
            intent._cosign_as_fee_payer(envelope_hex, CURRENCY)

    def test_cosign_rejects_non_expiring_nonce_key(self) -> None:
        """Server should reject an envelope with a non-expiring nonce key."""
        from mpp.methods.tempo import TempoAccount, tempo
        from mpp.methods.tempo.intents import ChargeIntent
        from mpp.server.intent import VerificationError

        signed = _make_signed_tx()
        encoded = encode_fee_payer_envelope(signed)

        # Tamper nonce_key (index 6) to a non-MAX value
        decoded_fields = rlp.decode(encoded[1:])
        decoded_fields[6] = (42).to_bytes(1, "big")
        tampered = bytes([0x78]) + bytes(rlp.encode(decoded_fields))
        tampered_hex = "0x" + tampered.hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        with pytest.raises(VerificationError, match="expiring nonce key"):
            intent._cosign_as_fee_payer(tampered_hex, CURRENCY)

    def test_cosign_rejects_missing_valid_before(self) -> None:
        """Server should reject an envelope without valid_before."""
        from mpp.methods.tempo import TempoAccount, tempo
        from mpp.methods.tempo.intents import ChargeIntent
        from mpp.server.intent import VerificationError

        signed = _make_signed_tx(valid_before=None)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        with pytest.raises(VerificationError, match="must include valid_before"):
            intent._cosign_as_fee_payer(envelope_hex, CURRENCY)

    def test_cosign_rejects_expired_valid_before(self) -> None:
        """Server should reject an envelope with valid_before in the past."""
        from mpp.methods.tempo import TempoAccount, tempo
        from mpp.methods.tempo.intents import ChargeIntent
        from mpp.server.intent import VerificationError

        signed = _make_signed_tx(valid_before=1)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

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

    def test_cosign_preserves_full_t6_key_authorization(self) -> None:
        """encode -> decode -> cosign must keep the full T6 payload byte-exact.

        The sender signs a hash that includes ``key_authorization.as_rlp_payload()``.
        If decoding drops any signed field (``limits``/``allowed_calls``/``witness``/
        ``is_admin``/``account``), the recomputed sender hash changes and cosign
        fails with "Sender address does not match recovered signer".
        """
        from mpp.methods.tempo import TempoAccount, tempo
        from mpp.methods.tempo.intents import ChargeIntent

        signed = _sign_tx_with_key_auth(_T6_KEY_AUTH_PAYLOAD)
        envelope_hex = "0x" + encode_fee_payer_envelope(signed).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        # Succeeds only if the sender hash matched -> the full payload round-tripped.
        result = intent._cosign_as_fee_payer(envelope_hex, CURRENCY)
        assert result.startswith("0x76")

        # keyAuthorization sits at index 13 in the 0x76 encoding (before sender sig).
        decoded = rlp.decode(bytes.fromhex(result[2:])[1:])
        assert len(decoded) == 15
        assert decoded[13] == _T6_KEY_AUTH_PAYLOAD

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

    def test_cosign_preserves_authorization_list(self) -> None:
        from mpp.methods.tempo import TempoAccount, tempo
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
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        # Succeeds only if the auth list was preserved into the recovery hash.
        result = intent._cosign_as_fee_payer(envelope_hex, CURRENCY)
        assert result.startswith("0x76")

        decoded = rlp.decode(bytes.fromhex(result[2:])[1:])
        assert decoded[12] == [b"\x77" * 20, b"\x88" * 32]


class TestKeychainSignatureRejected:
    """Access-key (keychain) signed envelopes must fail cleanly, not opaquely."""

    def test_cosign_rejects_keychain_signature(self) -> None:
        from mpp.methods.tempo import TempoAccount, tempo
        from mpp.methods.tempo.intents import ChargeIntent
        from mpp.server.intent import VerificationError

        signed = _make_signed_tx(valid_before=int(time.time()) + 300)
        encoded = encode_fee_payer_envelope(signed)

        # Replace the 65-byte sender signature (last field) with an 86-byte
        # keychain signature: 0x04 || root_account (20) || inner (65).
        decoded_fields = rlp.decode(encoded[1:])
        decoded_fields[-1] = b"\x04" + b"\x11" * 20 + b"\x22" * 65
        tampered = "0x" + (bytes([0x78]) + bytes(rlp.encode(decoded_fields))).hex()

        fee_payer = TempoAccount.from_key("0x" + "ab" * 32)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        tempo(fee_payer=fee_payer, rpc_url="https://rpc.test", intents={"charge": intent})

        with pytest.raises(VerificationError, match="keychain.*not supported"):
            intent._cosign_as_fee_payer(tampered, CURRENCY)
