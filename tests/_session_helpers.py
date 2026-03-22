"""Shared test helpers for session test modules."""

from __future__ import annotations

ESCROW = "0x5555555555555555555555555555555555555555"
CHAIN_ID = 42431
TEST_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def signer_address() -> str:
    from eth_account import Account

    return Account.from_key(TEST_KEY).address


def sign_voucher(
    amount: int,
    *,
    private_key: str = TEST_KEY,
    channel_id: str = "0x" + "ab" * 32,
    escrow: str = ESCROW,
    chain_id: int = CHAIN_ID,
) -> bytes:
    """Sign an EIP-712 voucher for testing."""
    from eth_account import Account

    channel_id_bytes = bytes.fromhex(
        channel_id[2:] if channel_id.startswith("0x") else channel_id
    )

    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Voucher": [
                {"name": "channelId", "type": "bytes32"},
                {"name": "cumulativeAmount", "type": "uint128"},
            ],
        },
        "primaryType": "Voucher",
        "domain": {
            "name": "Tempo Stream Channel",
            "version": "1",
            "chainId": chain_id,
            "verifyingContract": escrow,
        },
        "message": {
            "channelId": channel_id_bytes,
            "cumulativeAmount": amount,
        },
    }

    signed = Account.from_key(private_key).sign_typed_data(full_message=typed_data)
    return bytes(signed.signature)
