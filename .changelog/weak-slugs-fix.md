---
pympp: patch
---

Preserved the original signed transaction (instead of just the fee token) in the broadcast recovery record, ensuring retries reuse the same sponsored envelope across fee-token or sponsor-key changes. Claimed recovery records atomically using `put_if_absent` and retained replay protection when confirmed-payment cleanup is cancelled.
