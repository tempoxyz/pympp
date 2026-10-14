---
pympp: patch
---

Fixed the client silently returning a 5xx response to a paid retry. `PaymentTransport` now emits `payment.failed` with a `PaymentOutcomeUnknownError` carrying the credential, so callers can reconcile a payment the server may have settled before failing; the response is still returned and never retried. `PaymentOutcomeUnknownError` gains a `transaction_hash` attribute, populated for unsponsored Tempo charges. Before failure hooks run, the 5xx body is buffered up to 64 KiB within 2 seconds so its connection is released; a cut-off body sets `response.extensions["mpp.body_truncated"]`. Cancelling the request while failure hooks run raises `PaymentOutcomeUnknownError` instead of losing the outcome.
