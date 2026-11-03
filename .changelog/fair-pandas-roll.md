---
pympp: minor
---

Added OUSD as a third default auto-swap currency (after pathUSD and USDC.e) and introduced a `fallback: bool = True` field on `AutoSwap` that, when set to `False`, restricts swaps exclusively to the currencies listed in `token_in`.

Fixed unsponsored Tempo session opens and top-ups signing an auto-swap that bought the transaction fee on top of the deposit, which servers reject. A payer holding less of the channel token than the fee now fails locally with a `TransactionError`.
