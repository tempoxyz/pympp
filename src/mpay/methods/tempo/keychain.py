"""Tempo AccountKeychain signature handling.

Keychain signatures allow an access key to sign transactions on behalf
of a root account. The signature format is:

    0x03 || root_address (20 bytes) || inner_signature (65 bytes)

Total: 86 bytes
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mpay.methods.tempo.account import TempoAccount

KEYCHAIN_SIGNATURE_TYPE = 0x03
KEYCHAIN_SIGNATURE_LENGTH = 86

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


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
        ValueError: If root_account is not a valid Ethereum address.
    """
    if not ADDRESS_RE.match(root_account):
        raise ValueError(f"Invalid root_account address format: {root_account}")

    inner_sig = access_key.sign_hash(msg_hash)
    root_bytes = bytes.fromhex(root_account[2:])

    keychain_sig = bytes([KEYCHAIN_SIGNATURE_TYPE]) + root_bytes + inner_sig
    if len(keychain_sig) != KEYCHAIN_SIGNATURE_LENGTH:
        raise ValueError(
            f"Invalid keychain signature length: expected {KEYCHAIN_SIGNATURE_LENGTH}, "
            f"got {len(keychain_sig)}"
        )
    return keychain_sig
