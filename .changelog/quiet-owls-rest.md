---
pympp: patch
---

Preserve the original signed transaction when reconciling sponsored charges across fee-token or sponsor-key changes. Claim recovery records atomically and retain replay protection when confirmed-payment cleanup is cancelled.

Expire temporary recovery records after the authenticated challenge and transaction inclusion deadlines in the built-in stores without extending retention on retries.

Redis-backed sponsored recovery now requires Redis server 6.2 or later for atomic absolute expiry.
