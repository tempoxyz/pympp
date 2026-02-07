"""Shared defaults for Tempo payment method."""

# Mainnet
CHAIN_ID = 4217
RPC_URL = "https://rpc.tempo.xyz"
PATH_USD = "0x20c0000000000000000000000000000000000000"
PATH_USD_DECIMALS = 6

# Testnet
TESTNET_CHAIN_ID = 42431
TESTNET_RPC_URL = "https://rpc.testnet.tempo.xyz"
ALPHA_USD = "0x20c0000000000000000000000000000000000001"
ESCROW_CONTRACT = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"

# Testnet only — the fee payer service sponsors gas on testnet.
# On mainnet, the server itself must pay gas or provide its own fee payer.
DEFAULT_FEE_PAYER_URL = "https://sponsor.moderato.tempo.xyz"
