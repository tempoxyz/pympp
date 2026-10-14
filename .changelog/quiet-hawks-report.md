---
pympp: patch
---

Fixed the client silently returning a 5xx response to a paid retry. `PaymentTransport` now emits `payment.failed` with a `PaymentOutcomeUnknownError` carrying the credential, so callers can reconcile a payment the server may have settled before failing; the response is still returned and never retried. `PaymentOutcomeUnknownError` gains a `transaction_hash` attribute, populated for unsponsored Tempo charges.
