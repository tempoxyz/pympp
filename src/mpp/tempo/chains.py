"""Tempo chains and the first-party contract deployments mpp relies on."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

__all__ = [
    "ACCOUNT_KEYCHAIN",
    "CHAINS",
    "ESCROW_CONTRACTS",
    "FEE_MANAGER",
    "MAINNET_CHAIN_ID",
    "RPC_URLS",
    "STABLECOIN_DEX",
    "TEMPO",
    "TEMPO_MODERATO",
    "TESTNET_CHAIN_ID",
    "Chain",
    "resolve_chain_id",
]


MAINNET_CHAIN_ID: Final = 4217
"""Tempo mainnet chain ID."""

TESTNET_CHAIN_ID: Final = 42431
"""Tempo Moderato testnet chain ID."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Chain:
    id: int
    name: str
    rpc_url: str
    explorer_url: str
    testnet: bool = False


TEMPO: Final = Chain(
    id=MAINNET_CHAIN_ID,
    name="Tempo Mainnet",
    rpc_url="https://rpc.tempo.xyz",
    explorer_url="https://explore.tempo.xyz",
)

TEMPO_MODERATO: Final = Chain(
    id=TESTNET_CHAIN_ID,
    name="Tempo Testnet (Moderato)",
    rpc_url="https://rpc.moderato.tempo.xyz",
    explorer_url="https://explore.testnet.tempo.xyz",
    testnet=True,
)

CHAINS: Final = MappingProxyType({TEMPO.id: TEMPO, TEMPO_MODERATO.id: TEMPO_MODERATO})

RPC_URLS: Final = MappingProxyType({chain.id: chain.rpc_url for chain in CHAINS.values()})
"""Default RPC URL per Tempo chain."""

ESCROW_CONTRACTS: Final = MappingProxyType(
    {
        MAINNET_CHAIN_ID: "0x33b901018174DDabE4841042ab76ba85D4e24f25",
        TESTNET_CHAIN_ID: "0xe1c4d3dce17bc111181ddf716f75bae49e61a336",
    }
)
"""Default payment-channel escrow contract per chain."""

STABLECOIN_DEX: Final = "0xdec0000000000000000000000000000000000000"
"""Stablecoin DEX precompile."""

FEE_MANAGER: Final = "0xfeec000000000000000000000000000000000000"
"""Fee manager precompile (user fee-token preferences)."""

ACCOUNT_KEYCHAIN: Final = "0xaAAAaaAA00000000000000000000000000000000"
"""Account keychain precompile (access keys)."""


def resolve_chain_id(*, chain_id: int | None = None, testnet: bool = False) -> int:
    """Returns ``chain_id`` or the default mainnet/testnet chain ID."""
    if chain_id is not None:
        return chain_id
    return TESTNET_CHAIN_ID if testnet else MAINNET_CHAIN_ID
