"""Currency metadata accepted by EVM and x402 payment config.

A currency is one of:

* a raw ``0x`` token address (no chain or decimals metadata),
* a :class:`KnownAsset` — address, decimals, network and EIP-712 transfer metadata
  (see :func:`define` and the built-in ``BASE_USDC``, ``BASE_SEPOLIA_USDC``, ...),
* a :class:`Token` — a chain-indexed token definition (the Python equivalent of
  ``viem/tokens``; see :mod:`mpp.evm.tokens`).
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Literal

from mpp.x402._types import EVM_NETWORK_PREFIX

__all__ = [
    "BASE_SEPOLIA_USDC",
    "BASE_USDC",
    "CELO_SEPOLIA_USDC",
    "CELO_USDC",
    "CELO_USDT",
    "KNOWN_ASSETS",
    "Currency",
    "Eip3009Transfer",
    "ExactTransfer",
    "KnownAsset",
    "Permit2Transfer",
    "ResolvedCurrency",
    "ResolvedToken",
    "Token",
    "define",
    "from_token",
    "is_asset",
    "is_raw_address",
    "is_token",
    "matches",
    "resolve",
    "to_chain_id",
    "to_network",
]


_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}\Z")


@dataclass(frozen=True, slots=True, kw_only=True)
class Eip3009Transfer:
    """EIP-3009 ``transferWithAuthorization`` token domain metadata."""

    name: str
    version: str
    type: Literal["eip3009"] = field(default="eip3009", init=False)

    def __post_init__(self) -> None:
        if not self.name or not self.version:
            raise ValueError("EIP-3009 transfers require a non-empty name and version.")


@dataclass(frozen=True, slots=True, kw_only=True)
class Permit2Transfer:
    """Permit2 transfer metadata."""

    name: str | None = None
    version: str | None = None
    type: Literal["permit2"] = field(default="permit2", init=False)


type ExactTransfer = Eip3009Transfer | Permit2Transfer
"""Transfer configuration for exact EVM payments."""


@dataclass(frozen=True, slots=True, kw_only=True)
class KnownAsset:
    """Known x402/EVM asset metadata pinned to one network."""

    address: str
    decimals: int
    network: str
    transfer: ExactTransfer


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedToken:
    """A :class:`Token` resolved to a specific chain id."""

    address: str
    decimals: int
    currency: str | None = None
    name: str | None = None
    popular: bool | None = None
    symbol: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Token:
    """A chain-indexed token definition (``viem/tokens`` ``defineToken``).

    Call with a chain id to resolve the chain-specific token.
    """

    addresses: Mapping[int, str]
    decimals: int
    currency: str | None = None
    name: str | None = None
    popular: bool | None = None
    symbol: str | None = None

    def __call__(self, chain_id: int) -> ResolvedToken:
        address = self.addresses.get(chain_id)
        if not address:
            raise ValueError(f'Token has no address for chain id "{chain_id}".')
        return ResolvedToken(
            address=address,
            currency=self.currency,
            decimals=self.decimals,
            name=self.name,
            popular=self.popular,
            symbol=self.symbol,
        )


type Currency = str | KnownAsset | Token
"""A raw token address, known asset metadata, or a token definition."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedCurrency:
    """Currency metadata resolved for one network."""

    address: str
    decimals: int | None = None
    name: str | None = None
    transfer: ExactTransfer | None = None


def define(*, address: str, decimals: int, network: str, transfer: ExactTransfer) -> KnownAsset:
    """Creates known asset metadata for a custom token."""
    return KnownAsset(address=address, decimals=decimals, network=network, transfer=transfer)


def from_token(
    token: Token,
    *,
    chain_id: int,
    transfer: ExactTransfer | None = None,
    version: str | None = None,
) -> KnownAsset:
    """Creates known asset metadata from a :class:`Token` definition.

    Pass an explicit ``transfer``, or only ``version`` to sign EIP-3009 authorizations with the
    token's own name as the EIP-712 domain name.

    Raises:
        ValueError: When the token has no address on ``chain_id``, or an implied EIP-3009
            transfer has no token name or version.
    """
    resolved = token(chain_id)
    if transfer is None:
        if not resolved.name:
            raise ValueError("EIP-3009 token assets require a token name.")
        if not version:
            raise ValueError("EIP-3009 token assets require a version.")
        transfer = Eip3009Transfer(name=resolved.name, version=version)
    return define(
        address=resolved.address,
        decimals=resolved.decimals,
        network=to_network(chain_id),
        transfer=transfer,
    )


BASE_USDC: Final = define(
    address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    decimals=6,
    network="eip155:8453",
    # USDC's EIP-712 domain name differs between Base and Base Sepolia.
    transfer=Eip3009Transfer(name="USD Coin", version="2"),
)
"""USDC on Base."""

BASE_SEPOLIA_USDC: Final = define(
    address="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    decimals=6,
    network="eip155:84532",
    # Base Sepolia test USDC signs with the shorter EIP-712 domain name.
    transfer=Eip3009Transfer(name="USDC", version="2"),
)
"""USDC on Base Sepolia."""

CELO_USDC: Final = define(
    address="0xcebA9300f2b948710d2653dD7B07f33A8B32118C",
    decimals=6,
    network="eip155:42220",
    transfer=Eip3009Transfer(name="USDC", version="2"),
)
"""USDC on Celo."""

CELO_USDT: Final = define(
    address="0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e",
    decimals=6,
    network="eip155:42220",
    # Celo USDT signs with domain version "1", unlike Circle's FiatToken "2".
    transfer=Eip3009Transfer(name="Tether USD", version="1"),
)
"""USDT on Celo."""

CELO_SEPOLIA_USDC: Final = define(
    address="0x01C5C0122039549AD1493B8220cABEdD739BC44E",
    decimals=6,
    network="eip155:11142220",
    transfer=Eip3009Transfer(name="USDC", version="2"),
)
"""USDC on Celo Sepolia."""

KNOWN_ASSETS: Final = (BASE_USDC, BASE_SEPOLIA_USDC, CELO_USDC, CELO_USDT, CELO_SEPOLIA_USDC)
"""All built-in known assets."""


def is_asset(value: object) -> bool:
    """Returns whether ``value`` is :class:`KnownAsset` metadata."""
    return isinstance(value, KnownAsset)


def is_token(value: object) -> bool:
    """Returns whether ``value`` is a :class:`Token` definition."""
    return isinstance(value, Token)


def is_raw_address(currency: Currency) -> bool:
    """Returns whether a currency is a raw address without chain metadata."""
    return isinstance(currency, str)


def resolve(currency: Currency, network: str) -> ResolvedCurrency | None:
    """Resolves currency metadata for an EVM network (``None`` when unavailable there)."""
    if isinstance(currency, KnownAsset):
        if currency.network != network:
            return None
        return ResolvedCurrency(
            address=currency.address, decimals=currency.decimals, transfer=currency.transfer
        )
    if isinstance(currency, Token):
        address = currency.addresses.get(to_chain_id(network))
        if not address:
            return None
        return ResolvedCurrency(address=address, decimals=currency.decimals, name=currency.name)
    return ResolvedCurrency(address=currency)


def matches(currency: Currency, accepted_currency: str, network: str) -> bool:
    """Returns whether ``currency`` resolves to ``accepted_currency`` on ``network``.

    Raises:
        ValueError: When either address is malformed.
    """
    resolved = resolve(currency, network)
    if resolved is None:
        return False
    return _normalize(resolved.address) == _normalize(accepted_currency)


def to_network(chain_id: int) -> str:
    """Converts an EVM chain id to a CAIP-2 network identifier."""
    return f"{EVM_NETWORK_PREFIX}{chain_id}"


def to_chain_id(network: str) -> int:
    """Converts a CAIP-2 EVM network identifier to a chain id."""
    return int(network[len(EVM_NETWORK_PREFIX) :])


def _normalize(address: str) -> str:
    if not _ADDRESS.match(address):
        raise ValueError(f'Address "{address}" is invalid.')
    return address.lower()
