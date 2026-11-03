---
pympp: minor
---

Added OUSD as a third default auto-swap currency (after pathUSD and USDC.e) and introduced a `fallback: bool = True` field on `AutoSwap` that, when set to `False`, restricts swaps exclusively to the currencies listed in `token_in`.
