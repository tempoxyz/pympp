"""Shared defaults for Tempo payment method."""

from types import MappingProxyType

# Mainnet
CHAIN_ID = 4217
RPC_URL = "https://rpc.tempo.xyz"
PATH_USD = "0x20c0000000000000000000000000000000000000"
USDC = "0x20C000000000000000000000b9537d11c60E8b50"
MACH = "0x20c000000000000000000000f37de3740ADec032"
# OUSD uses the same TIP-20 address on mainnet and Moderato.
OUSD = "0x20c0000000000000000000006a37DA5C996874BE"
PATH_USD_DECIMALS = 6

# Testnet (Moderato)
TESTNET_CHAIN_ID = 42431
TESTNET_RPC_URL = "https://rpc.moderato.tempo.xyz"

# Chain ID -> default currency mapping
# Mainnet defaults to USDC, testnet defaults to pathUSD
DEFAULT_CURRENCIES: MappingProxyType[int, str] = MappingProxyType(
    {
        CHAIN_ID: USDC,
        TESTNET_CHAIN_ID: PATH_USD,
    }
)

# Chain ID -> currencies a server accepts by default, in offer order.
# OUSD is offered first; it is not a fee token.
DEFAULT_ACCEPTED_CURRENCIES: MappingProxyType[int, tuple[str, ...]] = MappingProxyType(
    {
        CHAIN_ID: (OUSD, USDC),
        TESTNET_CHAIN_ID: (OUSD, PATH_USD),
    }
)

# MACH is closed-loop payment credit, not a supported Tempo gas token.
FEE_TOKENS: MappingProxyType[int, tuple[str, ...]] = MappingProxyType(
    {
        CHAIN_ID: (PATH_USD, USDC),
        TESTNET_CHAIN_ID: (PATH_USD,),
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
        CHAIN_ID: "0x33b901018174DDabE4841042ab76ba85D4e24f25",
        TESTNET_CHAIN_ID: "0xe1c4d3dce17bc111181ddf716f75bae49e61a336",
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

    Returns USDC only for explicit mainnet (4217).
    Returns pathUSD for testnet, unknown chains, and None.
    """
    if chain_id is None:
        return PATH_USD
    return DEFAULT_CURRENCIES.get(chain_id, PATH_USD)


def default_currencies_for_chain(chain_id: int | None) -> tuple[str, ...]:
    """Return the currencies a server accepts by default, in offer order.

    Returns OUSD then USDC.e for mainnet (4217) and OUSD then pathUSD for
    Moderato (42431). Unknown chains and None accept only
    :func:`default_currency_for_chain`.
    """
    if chain_id is not None and chain_id in DEFAULT_ACCEPTED_CURRENCIES:
        return DEFAULT_ACCEPTED_CURRENCIES[chain_id]
    return (default_currency_for_chain(chain_id),)


def fee_tokens_for_chain(chain_id: int) -> tuple[str, ...]:
    """Return supported Tempo fee tokens in preference order."""
    return FEE_TOKENS.get(chain_id, (PATH_USD,))


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
