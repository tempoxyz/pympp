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
