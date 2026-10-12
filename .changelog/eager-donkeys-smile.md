---
pympp: patch
---

Stopped requesting cached relay receipts during payment authorization by removing idempotency key headers from broadcast requests. Reused credentials are rejected by relay replay protection, so uncertain outcomes now require separate recovery before executing protected operations.
