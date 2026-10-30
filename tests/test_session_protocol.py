"""TIP-1034 protocol primitives: payload, request and receipt models, vouchers, channel IDs, ABI.

Edge cases of mppx precompile/Protocol.ts, Voucher.ts, Channel.ts and escrow ABI decoding
that the mppx-generated vectors in test_session_precompile.py do not reach.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from eth_account import Account
from pydantic import ValidationError

from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo.session import _abi as abi
from mpp.methods.tempo.session import _protocol as protocol
from mpp.methods.tempo.session import _voucher as voucher
from mpp.methods.tempo.session._channel import (
    compute_channel_id,
    expiring_nonce_hash,
    sender_signing_preimage,
)
from mpp.methods.tempo.session._protocol import (
    ESCROW_ADDRESS,
    ZERO_ADDRESS,
    ChannelDescriptor,
    NeedVoucherEvent,
    SessionReceipt,
    SessionRequest,
    SignedVoucher,
)

CHAIN_ID = 1337
CURRENCY = "0x20C0000000000000000000000000000000000000"
PAYER = TempoAccount.from_key("0x" + "11" * 32)
OTHER = TempoAccount.from_key("0x" + "22" * 32)
CHANNEL_ID = "0x" + "ab" * 32
DESCRIPTOR = ChannelDescriptor(
    payer=PAYER.address,
    payee=OTHER.address,
    operator=ZERO_ADDRESS,
    token=CURRENCY,
    salt="0x" + "01" * 32,
    authorized_signer=ZERO_ADDRESS,
    expiring_nonce_hash="0x" + "cd" * 32,
)


class TestAmounts:
    def test_uint96_bounds(self) -> None:
        assert protocol.uint96(protocol.UINT96_MAX) == protocol.UINT96_MAX
        with pytest.raises(ValueError, match="uint96"):
            protocol.uint96(protocol.UINT96_MAX + 1)
        with pytest.raises(ValueError, match="uint96"):
            protocol.uint96(-1)

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("0", 0),
            ("123", 123),
            (str(protocol.UINT96_MAX), protocol.UINT96_MAX),
            (str(protocol.UINT96_MAX + 1), None),
            ("9" * 30, None),
            ("-1", None),
            ("1.5", None),
            ("", None),
        ],
    )
    def test_parse_uint96_amount(self, value: str, expected: int | None) -> None:
        assert protocol.parse_uint96_amount(value) == expected


class TestDescriptor:
    def test_wire_round_trip(self) -> None:
        wire = DESCRIPTOR.to_wire()
        assert set(wire) == {
            "payer",
            "payee",
            "operator",
            "token",
            "salt",
            "authorizedSigner",
            "expiringNonceHash",
        }
        assert ChannelDescriptor.from_wire(wire) == DESCRIPTOR

    def test_from_wire_rejects_malformed_descriptors(self) -> None:
        wire = DESCRIPTOR.to_wire()
        with pytest.raises(ValueError, match="must be an object"):
            ChannelDescriptor.from_wire([wire])
        with pytest.raises(ValueError, match="missing authorizedSigner"):
            ChannelDescriptor.from_wire({k: v for k, v in wire.items() if k != "authorizedSigner"})
        with pytest.raises(ValueError, match="must be strings"):
            ChannelDescriptor.from_wire({**wire, "salt": 1})


class TestPayloads:
    def test_payload_descriptor_is_parsed_on_demand(self) -> None:
        payload = protocol.VoucherPayload.model_validate(
            {
                "action": "voucher",
                "channelId": CHANNEL_ID,
                "cumulativeAmount": "5",
                "signature": "0x01",
            }
        )
        assert payload.channel_descriptor() is None
        with_descriptor = payload.model_copy(update={"descriptor": DESCRIPTOR.to_wire()})
        assert with_descriptor.channel_descriptor() == DESCRIPTOR
        assert with_descriptor.to_wire()["descriptor"] == DESCRIPTOR.to_wire()

    def test_session_credential_actions(self) -> None:
        for action in ("open", "topUp", "voucher", "close"):
            assert protocol.is_session_credential_action(action)
        assert not protocol.is_session_credential_action("settle")
        assert not protocol.is_session_credential_action(None)


class TestSessionRequest:
    def _request(self, **fields: Any) -> dict[str, Any]:
        base: dict[str, Any] = {"amount": "0.5", "currency": CURRENCY, "decimals": 6}
        base["unitType"] = "token"
        base.update(fields)
        return SessionRequest.model_validate(base).model_dump()

    def test_minimal_request_always_has_method_details(self) -> None:
        assert self._request() == {
            "amount": "500000",
            "currency": CURRENCY,
            "unitType": "token",
            "methodDetails": {},
        }

    def test_full_request_serializes_every_method_detail(self) -> None:
        wire = self._request(
            recipient=OTHER.address,
            chainId=CHAIN_ID,
            channelId=CHANNEL_ID,
            escrowContract=ESCROW_ADDRESS,
            feePayer=PAYER,
            feeToken=CURRENCY,
            minVoucherDelta="0.01",
            operator=OTHER.address,
            sessionProtocol="v2",
            sessionSnapshot={"acceptedCumulative": "1"},
            suggestedDeposit="10",
        )
        assert wire["recipient"] == OTHER.address
        assert wire["suggestedDeposit"] == "10000000"
        assert wire["methodDetails"] == {
            "escrowContract": ESCROW_ADDRESS,
            "channelId": CHANNEL_ID,
            "minVoucherDelta": "10000",
            "chainId": CHAIN_ID,
            # A fee payer account is advertised as true, never serialized.
            "feePayer": True,
            "feeToken": CURRENCY,
            "operator": OTHER.address,
            "sessionProtocol": "v2",
            "sessionSnapshot": {"acceptedCumulative": "1"},
        }
        assert self._request(feePayer=False)["methodDetails"] == {"feePayer": False}

    @pytest.mark.parametrize(
        "fields",
        [
            {"amount": "0"},
            {"amount": "0.0000001"},
            {"suggestedDeposit": "0.0000001"},
            {"minVoucherDelta": "0.0000001"},
            {"feeToken": "0x1234"},
            {"sessionProtocol": "v3"},
        ],
    )
    def test_rejects_invalid_requests(self, fields: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            self._request(**fields)


def receipt_wire(**overrides: Any) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "method": "tempo",
        "intent": "session",
        "status": "success",
        "timestamp": "2026-01-01T00:00:00.000Z",
        "reference": CHANNEL_ID,
        "challengeId": "challenge",
        "channelId": CHANNEL_ID,
        "acceptedCumulative": "10",
        "spent": "5",
    }
    wire.update(overrides)
    return wire


class TestReceipts:
    def test_receipt_wire_round_trip_with_optional_fields(self) -> None:
        receipt = SessionReceipt.from_wire(receipt_wire(units=2, txHash="0x01"))
        assert (receipt.units, receipt.tx_hash) == (2, "0x01")
        encoded = protocol.serialize_session_receipt(receipt)
        assert "=" not in encoded
        assert protocol.deserialize_session_receipt(encoded) == receipt
        # Standard base64 with padding is accepted too.
        standard = base64.b64encode(json.dumps(receipt.to_wire()).encode()).decode()
        assert protocol.deserialize_session_receipt(standard) == receipt

    @pytest.mark.parametrize(
        "value",
        [
            None,
            receipt_wire(method="stripe"),
            receipt_wire(spent=5),
            receipt_wire(units=True),
            receipt_wire(units="2"),
            receipt_wire(txHash=1),
        ],
    )
    def test_rejects_invalid_receipts(self, value: Any) -> None:
        assert not protocol.is_session_receipt(value)
        with pytest.raises(ValueError, match="Invalid session receipt"):
            SessionReceipt.from_wire(value)

    def test_deserialize_rejects_garbage(self) -> None:
        with pytest.raises(ValueError, match="Invalid session receipt"):
            protocol.deserialize_session_receipt("!!!")
        with pytest.raises(ValueError, match="Invalid session receipt"):
            protocol.deserialize_session_receipt(base64.urlsafe_b64encode(b"\xff").decode())

    def test_create_session_receipt_uses_the_channel_as_reference(self) -> None:
        receipt = protocol.create_session_receipt(
            challenge_id="c", channel_id=CHANNEL_ID, accepted_cumulative=10, spent=4
        )
        assert receipt.reference == CHANNEL_ID
        assert (receipt.accepted_cumulative, receipt.spent) == ("10", "4")
        # JavaScript Date.toISOString(): millisecond precision with a Z suffix.
        assert len(receipt.timestamp) == 24 and receipt.timestamp.endswith("Z")

    def test_need_voucher_event_rejects_non_string_amounts(self) -> None:
        with pytest.raises(ValueError, match="need-voucher"):
            NeedVoucherEvent.from_wire({"channelId": CHANNEL_ID, "requiredCumulative": 1})
        with pytest.raises(ValueError, match="need-voucher"):
            NeedVoucherEvent.from_wire("event")


class TestVoucherSigning:
    def test_digest_requires_a_32_byte_channel_and_uint96_amount(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            voucher.voucher_digest(channel_id="0x1234", cumulative_amount=1, chain_id=CHAIN_ID)
        with pytest.raises(ValueError, match="uint96"):
            voucher.voucher_digest(
                channel_id=CHANNEL_ID, cumulative_amount=1 << 96, chain_id=CHAIN_ID
            )

    def test_signs_with_eth_account_and_normalizes_v(self) -> None:
        local = Account.from_key("0x" + "11" * 32)
        signature = voucher.sign_voucher(
            local, channel_id=CHANNEL_ID, cumulative_amount=7, chain_id=CHAIN_ID
        )
        assert signature == voucher.sign_voucher(
            PAYER, channel_id=CHANNEL_ID, cumulative_amount=7, chain_id=CHAIN_ID
        )

        class ParitySigner:
            """Returns a 0/1 recovery id, as raw secp256k1 signers do."""

            def sign_hash(self, msg_hash: bytes) -> bytes:
                raw = PAYER.sign_hash(msg_hash)
                return raw[:64] + bytes([raw[64] - 27 if raw[64] >= 27 else raw[64]])

        assert (
            voucher.sign_voucher(
                ParitySigner(), channel_id=CHANNEL_ID, cumulative_amount=7, chain_id=CHAIN_ID
            )
            == signature
        )

    def test_rejects_signers_it_cannot_use(self) -> None:
        with pytest.raises(TypeError, match="sign_hash"):
            voucher.sign_voucher(
                object(), channel_id=CHANNEL_ID, cumulative_amount=1, chain_id=CHAIN_ID
            )

        class KeychainSigner:
            def sign_hash(self, msg_hash: bytes) -> bytes:
                return b"\x03" + b"\x00" * 85

        with pytest.raises(ValueError, match="TIP-1020 primitive signature"):
            voucher.sign_close_authorization(
                KeychainSigner(), channel_id=CHANNEL_ID, cumulative_amount=1, chain_id=CHAIN_ID
            )


class TestVoucherVerification:
    def _signed(
        self, signature: str, amount: int = 7, channel_id: str = CHANNEL_ID
    ) -> SignedVoucher:
        return SignedVoucher(channel_id=channel_id, cumulative_amount=amount, signature=signature)

    def test_rejects_malformed_signatures_and_inputs(self) -> None:
        good = voucher.sign_voucher(
            PAYER, channel_id=CHANNEL_ID, cumulative_amount=7, chain_id=CHAIN_ID
        )
        verify = voucher.verify_voucher
        assert verify(ESCROW_ADDRESS, CHAIN_ID, self._signed(good), PAYER.address)
        for bad in ("0xzz", good[2:], good[:-2] + "00", "0x" + "00" * 64 + "1b"):
            assert not verify(ESCROW_ADDRESS, CHAIN_ID, self._signed(bad), PAYER.address)
        assert not verify(ESCROW_ADDRESS, CHAIN_ID, self._signed(good, amount=-1), PAYER.address)
        assert not verify(
            ESCROW_ADDRESS, CHAIN_ID, self._signed(good, channel_id="0x12"), PAYER.address
        )

    def test_close_authorization_accepts_any_expected_signer(self) -> None:
        close = voucher.sign_close_authorization(
            OTHER, channel_id=CHANNEL_ID, cumulative_amount=7, chain_id=CHAIN_ID
        )
        verify = voucher.verify_close_authorization
        signed = self._signed(close)
        assert verify(ESCROW_ADDRESS, CHAIN_ID, signed, [PAYER.address, OTHER.address.lower()])
        assert not verify(ESCROW_ADDRESS, CHAIN_ID, signed, [PAYER.address])
        assert not verify(
            ESCROW_ADDRESS, CHAIN_ID, self._signed(close, amount=1 << 96), [OTHER.address]
        )

    def test_parse_voucher_from_payload(self) -> None:
        parsed = voucher.parse_voucher_from_payload(CHANNEL_ID, "7", "0x01")
        assert parsed == self._signed("0x01")
        with pytest.raises(ValueError, match="uint96"):
            voucher.parse_voucher_from_payload(CHANNEL_ID, str(1 << 96), "0x01")


class TestChannel:
    def test_channel_id_depends_on_chain_and_escrow(self) -> None:
        base = compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID)
        assert compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID + 1) != base
        assert compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID, escrow=ZERO_ADDRESS) != base

    def test_rejects_malformed_tempo_transactions(self) -> None:
        from mpp.methods.tempo import _rlp as rlp

        with pytest.raises(ValueError, match="Malformed"):
            sender_signing_preimage("0x76" + rlp.encode([b"\x01", b"\x02"]).hex())
        with pytest.raises(ValueError, match="Tempo"):
            sender_signing_preimage("0x76zz")

    def test_expiring_nonce_hash_requires_a_20_byte_sender(self) -> None:
        with pytest.raises(ValueError, match="20-byte"):
            expiring_nonce_hash("0x76c0", "0x1234")


class TestAbi:
    def test_rejects_short_bytes32_values(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            abi.encode_get_channel_state("0x1234")

    @pytest.mark.parametrize("data", ["0xzz", "0x00000000", abi.encode_request_close(DESCRIPTOR)])
    def test_decode_open_rejects_other_calldata(self, data: str) -> None:
        with pytest.raises(ValueError, match="Expected TIP-1034 open calldata"):
            abi.decode_open(data)

    def test_decode_open_rejects_truncated_arguments(self) -> None:
        with pytest.raises(ValueError, match="Expected TIP-1034 open calldata"):
            abi.decode_open("0x" + abi.SELECTORS["open"].hex() + "00" * 31)

    def test_decode_event_without_topics(self) -> None:
        assert abi.decode_event([], "0x") is None
