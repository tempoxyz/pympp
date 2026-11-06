---
pympp: minor
---

Added `SQLStore`, a new atomic key-value store backend backed by SQL databases (Postgres and SQLite). Added `postgres` optional dependency using `asyncpg`, and exposed `SQLStore` and `SQLDriver` via `mpp.stores`.
