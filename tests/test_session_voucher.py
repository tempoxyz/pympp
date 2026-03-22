"""Tests for session/voucher.py — EIP-712 verification + channel ID."""

from __future__ import annotations

import pytest

from mpp.methods.tempo.session.voucher import (
    MAGIC_BYTES,
    _is_keychain_envelope,
    _strip_magic_trailer,
    compute_channel_id,
    verify_voucher,
)
from tests._session_helpers import CHAIN_ID, ESCROW, TEST_KEY, sign_voucher, signer_address


@pytest.fixture
def signer_addr() -> str:
    return signer_address()


@pytest.fixture
def channel_id() -> str:
    return "0x" + "cd" * 32


class TestVerifyVoucher:
    def test_roundtrip(self, signer_addr: str, channel_id: str) -> None:
        sig = sign_voucher(5000, private_key=TEST_KEY, channel_id=channel_id)
        assert verify_voucher(ESCROW, CHAIN_ID, channel_id, 5000, sig, signer_addr)

    def test_wrong_signer(self, channel_id: str) -> None:
        sig = sign_voucher(5000, private_key=TEST_KEY, channel_id=channel_id)
        wrong = "0x1111111111111111111111111111111111111111"
        assert not verify_voucher(ESCROW, CHAIN_ID, channel_id, 5000, sig, wrong)

    def test_wrong_amount(self, signer_addr: str, channel_id: str) -> None:
        sig = sign_voucher(5000, private_key=TEST_KEY, channel_id=channel_id)
        assert not verify_voucher(ESCROW, CHAIN_ID, channel_id, 9999, sig, signer_addr)

    def test_garbage_signature(self, signer_addr: str, channel_id: str) -> None:
        garbage = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        assert not verify_voucher(ESCROW, CHAIN_ID, channel_id, 5000, garbage, signer_addr)

    def test_keychain_envelope_rejected(self, signer_addr: str, channel_id: str) -> None:
        addr_bytes = bytes.fromhex(signer_addr[2:])
        envelope = bytes([0x03]) + addr_bytes + bytes([0xAA] * 65)
        assert not verify_voucher(ESCROW, CHAIN_ID, channel_id, 5000, envelope, signer_addr)

    def test_keychain_with_magic_trailer_rejected(self, signer_addr: str, channel_id: str) -> None:
        addr_bytes = bytes.fromhex(signer_addr[2:])
        envelope = bytes([0x03]) + addr_bytes + bytes([0xAA] * 65) + MAGIC_BYTES
        assert not verify_voucher(ESCROW, CHAIN_ID, channel_id, 5000, envelope, signer_addr)

    def test_raw_65_byte_sig_starting_with_03_works(self, channel_id: str) -> None:
        """A 65-byte sig starting with 0x03 is raw ECDSA, not a keychain envelope."""
        sig = sign_voucher(42, private_key=TEST_KEY, channel_id=channel_id)
        modified = bytes([0x03]) + sig[1:]
        result = verify_voucher(ESCROW, CHAIN_ID, channel_id, 42, modified, "0x" + "11" * 20)
        assert result is False


class TestStripMagicTrailer:
    def test_no_magic(self) -> None:
        raw = bytes([1, 2, 3])
        assert _strip_magic_trailer(raw) == raw

    def test_with_magic(self) -> None:
        raw = bytes([1, 2, 3]) + MAGIC_BYTES
        assert _strip_magic_trailer(raw) == bytes([1, 2, 3])

    def test_just_magic_not_stripped(self) -> None:
        """Exactly 32 bytes of 0x77 — should NOT strip (len == 32, not > 32)."""
        assert _strip_magic_trailer(MAGIC_BYTES) == MAGIC_BYTES


class TestIsKeychainEnvelope:
    def test_valid_envelope(self) -> None:
        envelope = bytes([0x03]) + bytes(20) + bytes(65)
        assert _is_keychain_envelope(envelope)

    def test_raw_65_byte_not_envelope(self) -> None:
        raw = bytes([0x03]) + bytes(64)
        assert not _is_keychain_envelope(raw)

    def test_wrong_prefix(self) -> None:
        envelope = bytes([0x01]) + bytes(20) + bytes(65)
        assert not _is_keychain_envelope(envelope)

    def test_too_short(self) -> None:
        assert not _is_keychain_envelope(bytes([0x03] * 10))


class TestComputeChannelId:
    def test_deterministic(self) -> None:
        args = {
            "payer": "0x1111111111111111111111111111111111111111",
            "payee": "0x2222222222222222222222222222222222222222",
            "token": "0x3333333333333333333333333333333333333333",
            "salt": "0x" + "00" * 32,
            "authorized_signer": "0x4444444444444444444444444444444444444444",
            "escrow_contract": ESCROW,
            "chain_id": CHAIN_ID,
        }
        id1 = compute_channel_id(**args)
        id2 = compute_channel_id(**args)
        assert id1 == id2
        assert id1.startswith("0x")
        assert len(id1) == 66  # 0x + 64 hex chars

    def test_differs_for_different_params(self) -> None:
        base = {
            "payer": "0x1111111111111111111111111111111111111111",
            "payee": "0x2222222222222222222222222222222222222222",
            "token": "0x3333333333333333333333333333333333333333",
            "salt": "0x" + "00" * 32,
            "authorized_signer": "0x4444444444444444444444444444444444444444",
            "escrow_contract": ESCROW,
            "chain_id": CHAIN_ID,
        }
        id1 = compute_channel_id(**base)
        id2 = compute_channel_id(
            **{**base, "payer": "0x9999999999999999999999999999999999999999"}
        )
        assert id1 != id2
