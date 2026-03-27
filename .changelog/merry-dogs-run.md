---
pympp: minor
---

Added `RedisStore` and `SQLiteStore` backends to `mpp.stores` for replay protection, with optional extras (`pympp[redis]`, `pympp[sqlite]`). Added `store` parameter to `Mpp.__init__` and `Mpp.create()` that automatically wires the store into intents supporting replay protection.
