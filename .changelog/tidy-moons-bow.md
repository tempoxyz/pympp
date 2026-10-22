---
pympp: patch
---

Fixed payment gate context binding so `meta` is forwarded through direct `Mpp.charge()` and `Mpp.pay()` verification. HTTP framework scope now includes the request method and merges with configured `_mppx_scope` instead of skipping automatic binding. Server-issued challenges now include a random HMAC-bound `_mpp_nonce` in opaque metadata to ensure uniqueness across callers even with fixed expirations.
