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
    from mpp.methods.tempo.account import TempoAccount

KEYCHAIN_SIGNATURE_TYPE = 0x03
KEYCHAIN_SIGNATURE_LENGTH = 86

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")


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
        ValueError: If msg_hash is not 32 bytes, root_account is not a
            0x-prefixed 20-byte hex address, or the signature is not 86 bytes.
    """
    if len(msg_hash) != 32:
        raise ValueError(f"msg_hash must be 32 bytes, got {len(msg_hash)}")
    if not _ADDRESS_RE.fullmatch(root_account):
        raise ValueError(
            f"root_account must be a 0x-prefixed 20-byte hex address: {root_account!r}"
        )

    inner_sig = access_key.sign_hash(msg_hash)
    root_bytes = bytes.fromhex(root_account[2:])

    keychain_sig = bytes([KEYCHAIN_SIGNATURE_TYPE]) + root_bytes + inner_sig
    if len(keychain_sig) != KEYCHAIN_SIGNATURE_LENGTH:
        raise ValueError(
            f"keychain signature must be {KEYCHAIN_SIGNATURE_LENGTH} bytes, got {len(keychain_sig)}"
        )
    return keychain_sig
