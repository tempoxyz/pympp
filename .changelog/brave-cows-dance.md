---
pympp: minor
---

Added a `Settlement` class that custom `settle` hooks can return alongside a bare reference string, carrying settlement `extensions` for the receipt. Extended `SettleResponse` and `VerifyResponse` with an optional `extensions` field, and plumbed facilitator settle extensions through to receipts and the x402 `PAYMENT-RESPONSE` header.
