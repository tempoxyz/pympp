---
pympp: minor
---

Added `auto_swap` to the Tempo `charge()` client (`True` or an `AutoSwap` with currencies and slippage): when the payer lacks the charge currency, it buys the shortfall through the Tempo stablecoin DEX in the same transaction, or raises `InsufficientFundsError` when no fallback currency can fund it.
