---
pympp: patch
---

Preserve the original signed transaction when reconciling sponsored charges across fee-token or sponsor-key changes. Claim recovery records atomically and retain replay protection when confirmed-payment cleanup is cancelled.

Expire temporary recovery records at the authenticated challenge deadline in the built-in stores without extending retention on retries.
