---
pympp: patch
---

Changed Stripe PaymentIntent and Tempo relay idempotency keys to use the SDK-independent `mpp_` prefix while preserving their existing suffix construction.
