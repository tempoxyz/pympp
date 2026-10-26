---
pympp: minor
---

Added `SponsorBudget` to cap a local fee payer's aggregate in-flight sponsored fees across processes, with a new `sponsor_budget` parameter on `ChargeIntent` and `server.charge`. Added `CompareAndSetStore` protocol and implemented atomic `compare_and_set` on `MemoryStore`, `RedisStore`, and `SQLiteStore` to support shared budget state.
