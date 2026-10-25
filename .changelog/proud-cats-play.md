---
pympp: patch
---

Fixed replay claims in Redis and SQLite stores to persist independently of any configured TTL, ensuring that a successful `put_if_absent` claim remains protected until explicitly deleted. Added regression tests covering TTL expiry, store reopen, and global cleanup scenarios.
