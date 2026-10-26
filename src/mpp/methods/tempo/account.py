"""Tempo account management for signing transactions.

Wraps eth-account for key management and signing operations.
"""

from __future__ import annotations

import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from eth_account.signers.local import LocalAccount

WalletRequest = Callable[[str, list[Any]], Awaitable[Any]]
"""Sends one JSON-RPC request (method, params) to a wallet and returns its result."""


@dataclass(frozen=True)
class TempoAccount:
    """Wrapper around eth-account for signing.

    Example:
        # From hex private key
        account = TempoAccount.from_key("0x...")

        # From environment variable
        account = TempoAccount.from_env("TEMPO_PRIVATE_KEY")

        # Sign a hash
        signature = account.sign_hash(msg_hash)
    """

    _account: LocalAccount

    @classmethod
    def from_key(cls, private_key: str) -> TempoAccount:
        """Load from hex private key (0x-prefixed).

        Args:
            private_key: Hex-encoded private key with 0x prefix.

        Returns:
            A TempoAccount instance.
        """
        from eth_account import Account

        return cls(_account=Account.from_key(private_key))

    @classmethod
    def from_env(cls, var: str = "TEMPO_PRIVATE_KEY") -> TempoAccount:
        """Load from environment variable.

        Args:
            var: Environment variable name (default: TEMPO_PRIVATE_KEY).

        Returns:
            A TempoAccount instance.

        Raises:
            ValueError: If the environment variable is not set.
        """
        key = os.environ.get(var)
        if not key:
            raise ValueError(f"${var} not set")
        return cls.from_key(key)

    @property
    def address(self) -> str:
        """Get the account's Ethereum address."""
        return self._account.address

    @property
    def private_key(self) -> str:
        """Get the private key as hex string for signing.

        Note:
            This is intentionally exposed for use with pytempo's
            TempoTransaction.sign() method which requires the key as hex.
        """
        return self._account.key.hex()

    def sign_hash(self, msg_hash: bytes) -> bytes:
        """Sign a 32-byte hash, return 65-byte signature.

        Args:
            msg_hash: 32-byte hash to sign. Must be exactly 32 bytes.

        Returns:
            65-byte signature (r || s || v).

        Raises:
            ValueError: If msg_hash is not exactly 32 bytes.

        Note:
            This uses unsafe_sign_hash which does NOT apply EIP-191 prefix.
            For message signing with domain separation, use EIP-712 typed data
            or manually prefix with "\\x19Ethereum Signed Message:\\n32".
        """
        if len(msg_hash) != 32:
            raise ValueError(f"msg_hash must be 32 bytes, got {len(msg_hash)}")

        signed = self._account.unsafe_sign_hash(msg_hash)  # type: ignore[arg-type]
        return signed.r.to_bytes(32, "big") + signed.s.to_bytes(32, "big") + bytes([signed.v])


@dataclass(frozen=True)
class JsonRpcAccount:
    """An account whose wallet holds the key and signs over JSON-RPC.

    Charges paid with it prefer push mode: the wallet submits the transfer with
    EIP-5792 ``wallet_sendCalls`` (falling back to ``eth_sendTransaction`` for a
    single call). A pull-only challenge is signed with ``eth_signTransaction``.

    Example:
        account = JsonRpcAccount("0x...", request=wallet_request)

    Args:
        address: The wallet account's address.
        request: Sends a JSON-RPC request to the wallet. Defaults to the charge's
            ``rpc_url``, for a node that manages the account.
    """

    address: str
    request: WalletRequest | None = None

    def __post_init__(self) -> None:
        if re.fullmatch(r"0x[0-9a-fA-F]{40}", self.address):
            return
        if re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", self.address):
            raise ValueError(
                "JsonRpcAccount takes a wallet address, not a private key; "
                "use TempoAccount.from_key() for a local key"
            )
        raise ValueError("JsonRpcAccount address must be 0x followed by 40 hex characters")
