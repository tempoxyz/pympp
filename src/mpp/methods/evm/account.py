"""EVM account management for signing transactions.

Wraps eth-account for key management and signing operations.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from eth_account.signers.local import LocalAccount


@dataclass(frozen=True)
class EvmAccount:
    """Wrapper around eth-account for signing EVM transactions.

    Example:
        # From hex private key
        account = EvmAccount.from_key("0x...")

        # From environment variable
        account = EvmAccount.from_env("EVM_PRIVATE_KEY")
    """

    _account: LocalAccount

    @classmethod
    def from_key(cls, private_key: str) -> EvmAccount:
        """Load from hex private key (0x-prefixed)."""
        from eth_account import Account

        return cls(_account=Account.from_key(private_key))

    @classmethod
    def from_env(cls, var: str = "EVM_PRIVATE_KEY") -> EvmAccount:
        """Load from environment variable.

        Raises:
            ValueError: If the environment variable is not set.
        """
        key = os.environ.get(var)
        if not key:
            raise ValueError(f"${var} not set")
        return cls.from_key(key)

    @classmethod
    def from_file(cls, path: str) -> EvmAccount:
        """Load from a local file containing a hex private key.

        Args:
            path: Path to the key file. The file's contents are stripped of
                surrounding whitespace before use.

        Raises:
            ValueError: If the file is empty.
            FileNotFoundError: If the file does not exist.
        """
        key = Path(path).read_text().strip()
        if not key:
            raise ValueError(f"{path} is empty")
        return cls.from_key(key)

    @property
    def address(self) -> str:
        """Get the account's Ethereum address."""
        return self._account.address

    @property
    def private_key(self) -> str:
        """Get the private key as a hex string for signing."""
        return self._account.key.hex()
