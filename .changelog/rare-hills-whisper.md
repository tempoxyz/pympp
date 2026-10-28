---
pympp: minor
---

Added `SponsorBudget` to cap a local fee payer's aggregate in-flight sponsored fees across processes, with a new `sponsor_budget` parameter on `ChargeIntent` and `server.charge`. Added `CompareAndSetStore` protocol and implemented atomic `compare_and_set` on `MemoryStore`, `RedisStore` (requires `EVAL`), and `SQLiteStore` to support shared budget state. A store without usable `compare_and_set`, such as Redis denying `EVAL`, falls back to a process-scoped budget with a warning.
