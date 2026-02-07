"""EIP-712 voucher signing and verification.

Domain and types must exactly match the on-chain TempoStreamChannel
DOMAIN_SEPARATOR and VOUCHER_TYPEHASH.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mpay.methods.tempo.stream.types import SignedVoucher, Voucher

if TYPE_CHECKING:
    from mpay.methods.tempo.account import TempoAccount

# Must match the on-chain TempoStreamChannel DOMAIN_SEPARATOR name.
DOMAIN_NAME = "Tempo Stream Channel"
# Must match the on-chain TempoStreamChannel DOMAIN_SEPARATOR version.
DOMAIN_VERSION = "1"

# EIP-712 types for voucher signing.
# Matches @tempo/stream-channels/voucher and on-chain VOUCHER_TYPEHASH.
VOUCHER_TYPES = {
    "Voucher": [
        {"name": "channelId", "type": "bytes32"},
        {"name": "cumulativeAmount", "type": "uint128"},
    ],
}


def _get_voucher_domain(escrow_contract: str, chain_id: int) -> dict:
    """EIP-712 domain for voucher signing."""
    return {
        "name": DOMAIN_NAME,
        "version": DOMAIN_VERSION,
        "chainId": chain_id,
        "verifyingContract": escrow_contract,
    }


def _voucher_message(voucher: Voucher) -> dict:
    """Convert a Voucher to the EIP-712 message dict."""
    return {
        "channelId": bytes.fromhex(voucher.channel_id[2:]),
        "cumulativeAmount": voucher.cumulative_amount,
    }


def sign_voucher(
    account: TempoAccount,
    voucher: Voucher,
    escrow_contract: str,
    chain_id: int,
) -> str:
    """Sign a voucher with an account.

    Args:
        account: Account to sign with.
        voucher: Voucher to sign (channelId + cumulativeAmount).
        escrow_contract: Escrow contract address (0x-prefixed).
        chain_id: Chain ID for EIP-712 domain.

    Returns:
        0x-prefixed 65-byte hex signature.
    """
    domain = _get_voucher_domain(escrow_contract, chain_id)
    message = _voucher_message(voucher)

    signed = account._account.sign_typed_data(
        domain_data=domain,
        message_types=VOUCHER_TYPES,
        message_data=message,
    )
    return "0x" + signed.signature.hex()


def verify_voucher(
    escrow_contract: str,
    chain_id: int,
    voucher: SignedVoucher,
    expected_signer: str,
) -> bool:
    """Verify a voucher signature matches the expected signer.

    Args:
        escrow_contract: Escrow contract address (0x-prefixed).
        chain_id: Chain ID for EIP-712 domain.
        voucher: Signed voucher to verify.
        expected_signer: Expected signer address (0x-prefixed).

    Returns:
        True if the recovered signer matches expected_signer.
    """
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    try:
        domain = _get_voucher_domain(escrow_contract, chain_id)
        message = _voucher_message(voucher)

        signable = encode_typed_data(
            domain_data=domain,
            message_types=VOUCHER_TYPES,
            message_data=message,
        )

        sig_bytes = bytes.fromhex(voucher.signature[2:])
        if len(sig_bytes) != 65:
            return False

        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:64], "big")
        v = sig_bytes[64]

        recovered = Account.recover_message(signable, vrs=(v, r, s))
        return recovered.lower() == expected_signer.lower()
    except Exception:
        return False


def parse_voucher_from_payload(
    channel_id: str,
    cumulative_amount: str,
    signature: str,
) -> SignedVoucher:
    """Parse a voucher from credential payload fields.

    Args:
        channel_id: 0x-prefixed bytes32 hex.
        cumulative_amount: Decimal string amount.
        signature: 0x-prefixed 65-byte hex signature.

    Returns:
        A SignedVoucher instance.
    """
    return SignedVoucher(
        channel_id=channel_id,
        cumulative_amount=int(cumulative_amount),
        signature=signature,
    )
