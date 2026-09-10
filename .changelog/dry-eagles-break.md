---
pympp: patch
---

Fixed Stripe idempotent replay detection to reject replayed payments instead of accepting them. Updated both SDK client and raw HTTP paths to raise `VerificationFailedError` when a cached idempotent response is detected via the `Idempotent-Replayed` header.
