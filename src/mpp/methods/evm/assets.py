"""Known EVM assets that support EIP-3009 (mppx ``src/x402/Assets.ts``)."""

from __future__ import annotations

import re
from dataclasses import dataclass

BASE = 8453
"""Base mainnet chain ID."""

BASE_SEPOLIA = 84532
"""Base Sepolia testnet chain ID."""

CELO = 42220
"""Celo mainnet chain ID."""

CELO_SEPOLIA = 11142220
"""Celo Sepolia testnet chain ID."""

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")


@dataclass(frozen=True, slots=True)
class EvmAsset:
    """An EIP-3009 token on one EVM chain.

    Attributes:
        address: Token contract address.
        decimals: Token decimal places.
        chain_id: EVM chain ID.
        name: EIP-712 domain name the token signs authorizations with.
        version: EIP-712 domain version the token signs authorizations with.
    """

    address: str
    decimals: int
    chain_id: int
    name: str
    version: str

    def __post_init__(self) -> None:
        if not _ADDRESS_RE.fullmatch(self.address):
            raise ValueError(f"invalid token address: {self.address!r}")
        if isinstance(self.decimals, bool) or not isinstance(self.decimals, int):
            raise ValueError("decimals must be an integer")
        if not 0 <= self.decimals <= 36:
            raise ValueError("decimals must be between 0 and 36")
        if isinstance(self.chain_id, bool) or not isinstance(self.chain_id, int):
            raise ValueError("chain_id must be an integer")
        if self.chain_id <= 0:
            raise ValueError("chain_id must be positive")
        if not self.name or not self.version:
            raise ValueError("EIP-712 domain name and version are required")

    @property
    def network(self) -> str:
        """CAIP-2 network identifier, such as ``eip155:8453``."""
        return f"eip155:{self.chain_id}"


# USDC's EIP-712 domain name differs between Base and Base Sepolia.
BASE_USDC = EvmAsset(
    address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    decimals=6,
    chain_id=BASE,
    name="USD Coin",
    version="2",
)
"""USDC on Base."""

BASE_SEPOLIA_USDC = EvmAsset(
    address="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    decimals=6,
    chain_id=BASE_SEPOLIA,
    name="USDC",
    version="2",
)
"""USDC on Base Sepolia."""

CELO_USDC = EvmAsset(
    address="0xcebA9300f2b948710d2653dD7B07f33A8B32118C",
    decimals=6,
    chain_id=CELO,
    name="USDC",
    version="2",
)
"""USDC on Celo."""

# Celo USDT signs with domain version "1", unlike Circle's FiatToken "2".
CELO_USDT = EvmAsset(
    address="0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e",
    decimals=6,
    chain_id=CELO,
    name="Tether USD",
    version="1",
)
"""USDT on Celo."""

CELO_SEPOLIA_USDC = EvmAsset(
    address="0x01C5C0122039549AD1493B8220cABEdD739BC44E",
    decimals=6,
    chain_id=CELO_SEPOLIA,
    name="USDC",
    version="2",
)
"""USDC on Celo Sepolia."""
