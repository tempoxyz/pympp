---
pympp: patch
---

Added atomic `put_if_absent` method to `Store` protocol and `MemoryStore`, replacing the racy `get()`/`put()` pattern for charge replay protection. Normalized transaction hashes to lowercase before dedup to prevent mixed-case bypasses.
