---
pympp: patch
---

Added `Settlement`, which a custom EVM `settle` hook can return to report settlement `extensions`. Facilitator settle extensions now reach the receipt and the x402 `PAYMENT-RESPONSE` header.
