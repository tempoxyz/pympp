"""Shared defaults for the EVM payment method (e.g. Base)."""

from types import MappingProxyType

BASE_CHAIN_ID = 8453
BASE_SEPOLIA_CHAIN_ID = 84532

BASE_RPC_URL = "https://mainnet.base.org"
BASE_SEPOLIA_RPC_URL = "https://sepolia.base.org"

# Native USDC on Base. See https://developer.coinbase.com/base/usdc
BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

CHAIN_RPC_URLS: MappingProxyType[int, str] = MappingProxyType(
    {
        BASE_CHAIN_ID: BASE_RPC_URL,
        BASE_SEPOLIA_CHAIN_ID: BASE_SEPOLIA_RPC_URL,
    }
)

DEFAULT_CURRENCIES: MappingProxyType[int, str] = MappingProxyType(
    {
        BASE_CHAIN_ID: BASE_USDC,
        BASE_SEPOLIA_CHAIN_ID: BASE_SEPOLIA_USDC,
    }
)


def rpc_url_for_chain(chain_id: int) -> str:
    """Return the default RPC URL for a known EVM chain ID.

    Raises:
        ValueError: If the chain ID is not recognized.
    """
    url = CHAIN_RPC_URLS.get(chain_id)
    if url is None:
        raise ValueError(
            f"Unknown chain_id {chain_id}. Known chains: {list(CHAIN_RPC_URLS)}. "
            f"Pass rpc_url explicitly for custom chains."
        )
    return url


def default_currency_for_chain(chain_id: int | None) -> str | None:
    """Return the default USDC currency address for a known EVM chain ID.

    Returns ``None`` for unknown chains and when ``chain_id`` is ``None`` — there
    is no chain-agnostic default currency to fall back on for a custom chain.
    """
    if chain_id is None:
        return None
    return DEFAULT_CURRENCIES.get(chain_id)
