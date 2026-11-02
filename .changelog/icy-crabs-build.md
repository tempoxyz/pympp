---
pympp: patch
---

Preserved uncertain Stripe settlement outcomes (timeouts, server errors, ambiguous statuses) by raising `PaymentOutcomeUnknownError` instead of `VerificationFailedError`, retaining the original credential for reconciliation without offering replacement payments.
