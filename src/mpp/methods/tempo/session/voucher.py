"""EIP-712 voucher verification and channel ID computation.

Ported from mpp-rs ``voucher.rs``.  Uses ``eth_account`` for EIP-712
typed-data recovery and ``eth_utils.keccak`` for hashing (both
available transitively via pytempo).
"""

from __future__ import annotations

from eth_utils import keccak

DOMAIN_NAME = "Tempo Stream Channel"
DOMAIN_VERSION = "1"

KEYCHAIN_TYPE_PREFIX = 0x03
MAGIC_BYTES = bytes([0x77] * 32)


def _strip_magic_trailer(sig: bytes) -> bytes:
    """Strip trailing Tempo magic bytes if present."""
    if len(sig) > 32 and sig[-32:] == MAGIC_BYTES:
        return sig[:-32]
    return sig


def _is_keychain_envelope(sig: bytes) -> bool:
    """Return ``True`` if *sig* looks like a keychain envelope.

    Keychain format: ``0x03`` + 20-byte address + inner signature.
    A raw 65-byte ECDSA sig that happens to start with ``0x03``
    is *not* treated as a keychain envelope (len == 65 check first).
    """
    return len(sig) != 65 and len(sig) >= 21 and sig[0] == KEYCHAIN_TYPE_PREFIX


def verify_voucher(
    escrow_contract: str,
    chain_id: int,
    channel_id: str,
    cumulative_amount: int,
    signature_bytes: bytes,
    expected_signer: str,
) -> bool:
    """Verify a voucher signature via EIP-712 recovery.

    Returns ``True`` if *signature_bytes* is a valid EIP-712 voucher
    signature by *expected_signer*, ``False`` otherwise (never raises).

    SECURITY: keychain envelope signatures are rejected outright — the
    escrow contract only supports raw ECDSA via ``ecrecover``.
    """
    try:
        sig = _strip_magic_trailer(signature_bytes)

        if _is_keychain_envelope(sig):
            return False

        return _verify_voucher_ecdsa(
            escrow_contract, chain_id, channel_id, cumulative_amount, sig, expected_signer
        )
    except Exception:
        return False


def _verify_voucher_ecdsa(
    escrow_contract: str,
    chain_id: int,
    channel_id: str,
    cumulative_amount: int,
    signature_bytes: bytes,
    expected_signer: str,
) -> bool:
    """Raw ECDSA EIP-712 voucher verification."""
    from eth_account import Account
    from eth_account.messages import encode_typed_data

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
            "name": DOMAIN_NAME,
            "version": DOMAIN_VERSION,
            "chainId": chain_id,
            "verifyingContract": escrow_contract,
        },
        "message": {
            "channelId": channel_id_bytes,
            "cumulativeAmount": cumulative_amount,
        },
    }

    signable = encode_typed_data(full_message=typed_data)
    signing_hash = keccak(b"\x19\x01" + signable.header + signable.body)
    recovered = Account._recover_hash(signing_hash, signature=signature_bytes)
    return recovered.lower() == expected_signer.lower()


def compute_channel_id(
    payer: str,
    payee: str,
    token: str,
    salt: str,
    authorized_signer: str,
    escrow_contract: str,
    chain_id: int,
) -> str:
    """Compute channel ID.

    ``keccak256(abi.encode(payer, payee, token, salt, authorizedSigner,
    escrowContract, chainId))``

    All address/bytes32 args are hex strings (``0x``-prefixed).
    Returns the ``0x``-prefixed hex channel ID.
    """
    from eth_abi import encode

    salt_bytes = bytes.fromhex(salt[2:] if salt.startswith("0x") else salt)

    encoded = encode(
        ["address", "address", "address", "bytes32", "address", "address", "uint256"],
        [payer, payee, token, salt_bytes, authorized_signer, escrow_contract, chain_id],
    )
    return "0x" + keccak(encoded).hex()
