---
pympp: minor
---

Added configurable `max_payment_retries` parameter to `PaymentTransport` and `Client`, allowing callers to override the default retry limit of 3 instead of relying on a hardcoded constant.
