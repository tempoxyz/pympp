---
pympp: minor
---

Added chain-specific default currency selection: mainnet now defaults to USDC and testnet defaults to pathUSD. Exported `USDC`, `PATH_USD`, and `default_currency_for_chain` from the tempo package public API. Updated tests to reflect the new default currency behavior.
