"""Tests for Tempo keychain signature handling."""

import pytest

from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo.keychain import (
    KEYCHAIN_SIGNATURE_LENGTH,
    KEYCHAIN_SIGNATURE_TYPE,
    build_keychain_signature,
)

TEST_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class TestBuildKeychainSignature:
    def test_happy_path_format(self) -> None:
        """Should produce 86-byte signature: 0x03 || root_address || inner_sig."""
        access_key = TempoAccount.from_key(TEST_KEY)
        root_account = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        msg_hash = b"\xab" * 32

        sig = build_keychain_signature(msg_hash, access_key, root_account)

        assert len(sig) == KEYCHAIN_SIGNATURE_LENGTH
        assert sig[0] == KEYCHAIN_SIGNATURE_TYPE
        assert sig[1:21] == bytes.fromhex(root_account[2:])
        assert len(sig[21:]) == 65

    def test_inner_signature_is_deterministic(self) -> None:
        """Same hash + key should produce same inner signature."""
        access_key = TempoAccount.from_key(TEST_KEY)
        root_account = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
        msg_hash = b"\x01" * 32

        sig1 = build_keychain_signature(msg_hash, access_key, root_account)
        sig2 = build_keychain_signature(msg_hash, access_key, root_account)

        assert sig1 == sig2

    def test_different_root_accounts_produce_different_sigs(self) -> None:
        """Different root addresses should produce different signatures."""
        access_key = TempoAccount.from_key(TEST_KEY)
        msg_hash = b"\x00" * 32

        sig1 = build_keychain_signature(msg_hash, access_key, "0x" + "aa" * 20)
        sig2 = build_keychain_signature(msg_hash, access_key, "0x" + "bb" * 20)

        assert sig1[1:21] != sig2[1:21]
        # Inner sig is the same since msg_hash and key are the same
        assert sig1[21:] == sig2[21:]

    def test_invalid_root_address_too_short(self) -> None:
        """Should raise on root address with too few hex chars."""
        access_key = TempoAccount.from_key(TEST_KEY)
        msg_hash = b"\x00" * 32

        # Production code uses `assert` for length validation after building the signature
        with pytest.raises(AssertionError):
            build_keychain_signature(msg_hash, access_key, "0xdead")

    def test_invalid_root_address_not_hex(self) -> None:
        """Should raise on root address with invalid hex."""
        access_key = TempoAccount.from_key(TEST_KEY)
        msg_hash = b"\x00" * 32

        with pytest.raises(ValueError):
            build_keychain_signature(
                msg_hash, access_key, "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
            )

    def test_invalid_root_address_odd_length_hex(self) -> None:
        """Should raise on root address with odd-length hex string."""
        access_key = TempoAccount.from_key(TEST_KEY)
        msg_hash = b"\x00" * 32

        with pytest.raises(ValueError):
            build_keychain_signature(msg_hash, access_key, "0x" + "a" * 39)
