"""Shared defaults for Tempo payment method."""

# Mainnet
CHAIN_ID = 4217
RPC_URL = "https://rpc.tempo.xyz"
PATH_USD = "0x20c0000000000000000000000000000000000000"
PATH_USD_DECIMALS = 6

# Testnet (Moderato)
TESTNET_CHAIN_ID = 42431
TESTNET_RPC_URL = "https://rpc.moderato.tempo.xyz"
ESCROW_CONTRACT = "0x542831e3E4Ace07559b7C8787395f4Fb99F70787"

# Testnet only — the fee payer service sponsors gas on testnet.
# On mainnet, the server itself must pay gas or provide its own fee payer.
DEFAULT_FEE_PAYER_URL = "https://sponsor.moderato.tempo.xyz"

# Chain ID -> default RPC URL mapping
CHAIN_RPC_URLS: dict[int, str] = {
    CHAIN_ID: RPC_URL,
    TESTNET_CHAIN_ID: TESTNET_RPC_URL,
}


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
