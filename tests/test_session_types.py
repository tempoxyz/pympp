"""Tests for session/types.py — pydantic models and ChannelState."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mpp.errors import VerificationError
from mpp.methods.tempo.session.types import (
    ChannelState,
    ClosePayload,
    OpenPayload,
    SessionMethodDetails,
    TopUpPayload,
    VoucherPayload,
    parse_session_payload,
)


class TestOpenPayload:
    def test_parse_from_camel_case(self) -> None:
        data = {
            "action": "open",
            "type": "transaction",
            "channelId": "0xabc",
            "transaction": "0xtx",
            "cumulativeAmount": "100",
            "signature": "0xsig",
        }
        p = OpenPayload.model_validate(data)
        assert p.channel_id == "0xabc"
        assert p.cumulative_amount == "100"
        assert p.authorized_signer is None

    def test_authorized_signer_optional(self) -> None:
        data = {
            "action": "open",
            "type": "transaction",
            "channelId": "0xabc",
            "transaction": "0xtx",
            "authorizedSigner": "0xsigner",
            "cumulativeAmount": "100",
            "signature": "0xsig",
        }
        p = OpenPayload.model_validate(data)
        assert p.authorized_signer == "0xsigner"

    def test_rejects_non_transaction_type(self) -> None:
        data = {
            "action": "open",
            "type": "hash",
            "channelId": "0xabc",
            "transaction": "0xtx",
            "cumulativeAmount": "100",
            "signature": "0xsig",
        }
        with pytest.raises(ValidationError):
            OpenPayload.model_validate(data)

    def test_roundtrip(self) -> None:
        p = OpenPayload(
            action="open",
            type="transaction",
            channel_id="0xabc",
            transaction="0xtx",
            cumulative_amount="100",
            signature="0xsig",
        )
        d = p.model_dump(by_alias=True)
        assert d["channelId"] == "0xabc"
        assert d["cumulativeAmount"] == "100"
        p2 = OpenPayload.model_validate(d)
        assert p2.channel_id == p.channel_id


class TestTopUpPayload:
    def test_parse(self) -> None:
        data = {
            "action": "topUp",
            "type": "transaction",
            "channelId": "0xch",
            "transaction": "0xtx",
            "additionalDeposit": "5000",
        }
        p = TopUpPayload.model_validate(data)
        assert p.additional_deposit == "5000"

    def test_rejects_non_transaction_type(self) -> None:
        data = {
            "action": "topUp",
            "type": "hash",
            "channelId": "0xch",
            "transaction": "0xtx",
            "additionalDeposit": "5000",
        }
        with pytest.raises(ValidationError):
            TopUpPayload.model_validate(data)


class TestVoucherPayload:
    def test_parse(self) -> None:
        data = {
            "action": "voucher",
            "channelId": "0xch",
            "cumulativeAmount": "15000",
            "signature": "0xsig",
        }
        p = VoucherPayload.model_validate(data)
        assert p.cumulative_amount == "15000"

    def test_roundtrip(self) -> None:
        p = VoucherPayload(
            action="voucher",
            channel_id="0xch",
            cumulative_amount="15000",
            signature="0xsig",
        )
        d = p.model_dump(by_alias=True)
        assert "channelId" in d
        assert "type" not in d


class TestClosePayload:
    def test_parse(self) -> None:
        data = {
            "action": "close",
            "channelId": "0xch",
            "cumulativeAmount": "20000",
            "signature": "0xsig",
        }
        p = ClosePayload.model_validate(data)
        assert p.cumulative_amount == "20000"


class TestParseSessionPayload:
    def test_dispatches_all_actions(self) -> None:
        assert isinstance(
            parse_session_payload({
                "action": "open", "type": "transaction", "channelId": "0x",
                "transaction": "0x", "cumulativeAmount": "0", "signature": "0x",
            }),
            OpenPayload,
        )
        assert isinstance(
            parse_session_payload({
                "action": "topUp", "type": "transaction", "channelId": "0x",
                "transaction": "0x", "additionalDeposit": "0",
            }),
            TopUpPayload,
        )
        assert isinstance(
            parse_session_payload(
                {"action": "voucher", "channelId": "0x", "cumulativeAmount": "0", "signature": "0x"}
            ),
            VoucherPayload,
        )
        assert isinstance(
            parse_session_payload(
                {"action": "close", "channelId": "0x", "cumulativeAmount": "0", "signature": "0x"}
            ),
            ClosePayload,
        )

    def test_unknown_action_raises(self) -> None:
        with pytest.raises(VerificationError, match="Unknown session action"):
            parse_session_payload({"action": "refund"})


class TestSessionMethodDetails:
    def test_parse(self) -> None:
        data = {
            "escrowContract": "0xescrow",
            "channelId": "0xch",
            "minVoucherDelta": "500",
            "chainId": 42431,
            "feePayer": True,
        }
        d = SessionMethodDetails.model_validate(data)
        assert d.escrow_contract == "0xescrow"
        assert d.chain_id == 42431
        assert d.fee_payer is True

    def test_optional_fields(self) -> None:
        d = SessionMethodDetails.model_validate({})
        assert d.escrow_contract is None
        assert d.channel_id is None
        assert d.min_voucher_delta is None
        assert d.chain_id is None
        assert d.fee_payer is None


class TestChannelState:
    def test_construction(self) -> None:
        state = ChannelState(
            channel_id="0xch",
            chain_id=42431,
            escrow_contract="0xesc",
            payer="0xpayer",
            payee="0xpayee",
            token="0xtoken",
            authorized_signer="0xsigner",
            deposit=100_000,
            settled_on_chain=0,
            highest_voucher_amount=5000,
            highest_voucher_signature=b"\x00" * 65,
        )
        assert state.spent == 0
        assert state.units == 0
        assert state.finalized is False
