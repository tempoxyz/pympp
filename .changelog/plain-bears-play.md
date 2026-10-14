---
pympp: patch
---

Fixed the client silently ignoring 5xx responses to paid retries. `PaymentTransport` now emits `payment.failed` with a `PaymentOutcomeUnknownError` when a paid retry returns a server error, allowing callers to reconcile payments the server may have settled before failing. `PaymentOutcomeUnknownError` gained a `transaction_hash` attribute, populated for unsponsored Tempo charges to aid on-chain reconciliation.
