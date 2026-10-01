"""Tempo AccountKeychain signature handling.

Keychain signatures allow an access key to sign transactions on behalf
of a root account. The signature format is:

    0x03 || root_address (20 bytes) || inner_signature (65 bytes)

Total: 86 bytes
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mpp.methods.tempo.account import TempoAccount

KEYCHAIN_SIGNATURE_TYPE = 0x03
KEYCHAIN_SIGNATURE_LENGTH = 86


def build_keychain_signature(
    msg_hash: bytes,
    access_key: TempoAccount,
    root_account: str,
) -> bytes:
    """Build a Keychain signature for a message hash.

    Args:
        msg_hash: 32-byte hash to sign.
        access_key: The access key to sign with.
        root_account: Address of the root account (0x-prefixed).

    Returns:
        86-byte Keychain signature: 0x03 || root_account || inner_sig

    Raises:
        ValueError: If msg_hash length is invalid, root_account format is invalid,
            or the resulting signature length is not 86 bytes.
    """
    if len(msg_hash) != 32:
        msg = f"msg_hash must be exactly 32 bytes, got {len(msg_hash)}"
        raise ValueError(msg)

    if not isinstance(root_account, str) or not root_account.startswith("0x"):
        msg = f"root_account must be a 0x-prefixed hex string, got {root_account!r}"
        raise ValueError(msg)

    try:
        root_bytes = bytes.fromhex(root_account[2:])
    except ValueError as err:
        msg = f"Invalid hex in root_account: {err}"
        raise ValueError(msg) from err

    inner_sig = access_key.sign_hash(msg_hash)
    keychain_sig = bytes([KEYCHAIN_SIGNATURE_TYPE]) + root_bytes + inner_sig

    if len(keychain_sig) != KEYCHAIN_SIGNATURE_LENGTH:
        msg = (
            f"Keychain signature must be {KEYCHAIN_SIGNATURE_LENGTH} bytes, "
            f"got {len(keychain_sig)}"
        )
        raise ValueError(msg)
    return keychain_sig