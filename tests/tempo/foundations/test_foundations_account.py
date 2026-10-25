"""Port of mppx ``src/tempo/internal/account.test.ts``."""

from __future__ import annotations

import pytest

from mpp.tempo._internal.account import resolve, secp256k1_account
from mpp.tempo._internal.remote_fee_payer import RemoteFeePayer

ACCOUNT = secp256k1_account("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
FEE_PAYER = secp256k1_account("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")


class TestResolve:
    def test_normalizes_remote_fee_payer_string_shorthand(self) -> None:
        resolved = resolve(fee_payer="https://sponsor.example")
        assert resolved.fee_payer is None
        assert resolved.remote_fee_payer is not None
        assert resolved.remote_fee_payer.url == "https://sponsor.example"

    def test_preserves_remote_fee_payer_headers(self) -> None:
        remote_fee_payer = RemoteFeePayer(
            url="https://sponsor.example", headers={"Authorization": "Bearer test"}
        )
        resolved = resolve(fee_payer=remote_fee_payer)
        assert resolved.fee_payer is None
        assert resolved.remote_fee_payer is remote_fee_payer

    def test_preserves_local_account_and_account_sponsored_modes(self) -> None:
        assert resolve(account=ACCOUNT, fee_payer=FEE_PAYER).fee_payer is FEE_PAYER
        assert resolve(account=ACCOUNT, fee_payer=True).fee_payer is ACCOUNT


class TestKeychainInputs:
    # pympp#331: keychain signing validates its inputs with errors, not bare asserts.
    @pytest.mark.parametrize("access", ["not-an-address", "0x1234", "0x" + "zz" * 20, ""])
    def test_rejects_invalid_parent_account(self, access: str) -> None:
        with pytest.raises(ValueError, match="20-byte hex address"):
            secp256k1_account(
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", access=access
            )

    @pytest.mark.parametrize("raw", [True, False])
    @pytest.mark.parametrize("digest", [b"", b"abc", bytes(33)])
    def test_rejects_non_32_byte_digests(self, digest: bytes, raw: bool) -> None:
        access_key = secp256k1_account(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            access="0x" + "22" * 20,
        )
        for account in (ACCOUNT, access_key):
            with pytest.raises(ValueError, match="32 bytes"):
                account.sign(digest, raw=raw)
