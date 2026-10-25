"""Tempo stablecoin definitions and default payment currencies."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from mpp.tempo.chains import MAINNET_CHAIN_ID, TESTNET_CHAIN_ID, resolve_chain_id

__all__ = [
    "DECIMALS",
    "DEFAULT_CURRENCIES",
    "MACH_ADDRESS",
    "OUSD",
    "OUSD_ADDRESS",
    "PATH_USD",
    "PATH_USD_ADDRESS",
    "USDC_ADDRESS",
    "USDC_E",
    "Token",
    "resolve_currency",
]


DECIMALS: Final = 6
"""Default TIP-20 token decimals (every Tempo stablecoin uses 6)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Token:
    """A token with per-chain deployment addresses."""

    addresses: Mapping[int, str]
    decimals: int
    currency: str | None = None
    """ISO 4217 denomination, e.g. ``"USD"``."""
    name: str | None = None
    symbol: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "addresses", MappingProxyType(dict(self.addresses)))

    def address(self, chain_id: int) -> str:
        try:
            return self.addresses[chain_id]
        except KeyError:
            raise ValueError(f'Token has no address for chain id "{chain_id}".') from None


OUSD: Final = Token(
    addresses={
        1: "0x9f6F3991D525015a6F8CaF062C83b62fD3AC4436",
        MAINNET_CHAIN_ID: "0x20c0000000000000000000006a37DA5C996874BE",
        8453: "0xB2000000000000000000002fEb517dFeC7415344",
    },
    currency="USD",
    decimals=6,
    name="OpenUSD",
    symbol="OUSD",
)

PATH_USD: Final = Token(
    addresses={
        MAINNET_CHAIN_ID: "0x20c0000000000000000000000000000000000000",
        TESTNET_CHAIN_ID: "0x20c0000000000000000000000000000000000000",
    },
    currency="USD",
    decimals=6,
    name="PathUSD",
    symbol="pathUSD",
)

USDC_E: Final = Token(
    addresses={
        MAINNET_CHAIN_ID: "0x20c000000000000000000000b9537d11c60e8b50",
        TESTNET_CHAIN_ID: "0x20c0000000000000000000009e8d7eb59b783726",
    },
    currency="USD",
    decimals=6,
    name="Bridged USDC (Stargate)",
    symbol="USDC.e",
)

MACH_ADDRESS: Final = "0x20c000000000000000000000f37de3740ADec032"
"""Machine token (MACH) payment credit; it cannot pay transaction fees."""

OUSD_ADDRESS: Final = "0x20c0000000000000000000006a37DA5C996874BE"
"""OpenUSD, deployed at the same address on Tempo mainnet and Moderato."""

USDC_ADDRESS: Final = "0x20C000000000000000000000b9537d11c60E8b50"
"""USDC.e on Tempo mainnet (checksummed)."""

PATH_USD_ADDRESS: Final = "0x20c0000000000000000000000000000000000000"
"""pathUSD."""

DEFAULT_CURRENCIES: Final = MappingProxyType(
    {MAINNET_CHAIN_ID: USDC_ADDRESS, TESTNET_CHAIN_ID: PATH_USD_ADDRESS}
)
"""Default charge currency per chain."""


def resolve_currency(*, chain_id: int | None = None, testnet: bool = False) -> str:
    """Resolves the default currency, falling back to pathUSD on unknown chains."""
    return DEFAULT_CURRENCIES.get(
        resolve_chain_id(chain_id=chain_id, testnet=testnet), PATH_USD_ADDRESS
    )
