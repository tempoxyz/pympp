"""Shared defaults for Tempo payment method."""

from types import MappingProxyType

# Mainnet
CHAIN_ID = 4217
RPC_URL = "https://rpc.tempo.xyz"
PATH_USD = "0x20c0000000000000000000000000000000000000"
USDC = "0x20C000000000000000000000b9537d11c60E8b50"
PATH_USD_DECIMALS = 6

# Testnet (Moderato)
TESTNET_CHAIN_ID = 42431
TESTNET_RPC_URL = "https://rpc.moderato.tempo.xyz"

# Testnet only — the fee payer service sponsors gas on testnet.
# On mainnet, the server itself must pay gas or provide its own fee payer.
DEFAULT_FEE_PAYER_URL = "https://sponsor.moderato.tempo.xyz"

# Chain ID -> default currency mapping
# Mainnet defaults to USDC, testnet defaults to pathUSD
DEFAULT_CURRENCIES: MappingProxyType[int, str] = MappingProxyType(
    {
        CHAIN_ID: USDC,
        TESTNET_CHAIN_ID: PATH_USD,
    }
)

# Chain ID -> default RPC URL mapping
CHAIN_RPC_URLS: MappingProxyType[int, str] = MappingProxyType(
    {
        CHAIN_ID: RPC_URL,
        TESTNET_CHAIN_ID: TESTNET_RPC_URL,
    }
)

# Chain ID -> escrow contract address mapping (read-only)
ESCROW_CONTRACTS: MappingProxyType[int, str] = MappingProxyType(
    {
        CHAIN_ID: "0x0901aED692C755b870F9605E56BAA66c35BEfF69",
        TESTNET_CHAIN_ID: "0x542831e3E4Ace07559b7C8787395f4Fb99F70787",
    }
)


def rpc_url_for_chain(chain_id: int) -> str:
    """Return the default RPC URL for a known chain ID.

    Raises:
        ValueError: If the chain ID is not recognized.
    """
    url = CHAIN_RPC_URLS.get(chain_id)
    if url is None:
        raise ValueError(
            f"Unknown chain_id {chain_id}. "
            f"Known chains: {list(CHAIN_RPC_URLS)}. "
            f"Pass rpc_url explicitly for custom chains."
        )
    return url


def default_currency_for_chain(chain_id: int | None) -> str:
    """Return the default currency for a known chain ID.

    Returns USDC for mainnet, pathUSD for testnet and unknown chains.
    If chain_id is None, returns USDC (mainnet default).
    """
    if chain_id is None:
        return USDC
    return DEFAULT_CURRENCIES.get(chain_id, PATH_USD)


def escrow_contract_for_chain(chain_id: int) -> str:
    """Return the default escrow contract address for a known chain ID.

    Raises:
        ValueError: If the chain ID is not recognized.
    """
    addr = ESCROW_CONTRACTS.get(chain_id)
    if addr is None:
        raise ValueError(
            f"Unknown chain_id {chain_id}. "
            f"Known chains: {list(ESCROW_CONTRACTS)}. "
            f"Pass escrow_contract explicitly for custom chains."
        )
    return addr
