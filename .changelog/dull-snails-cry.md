---
pympp: patch
---

Added `SQLStore`, an atomic key-value store on Postgres or SQLite that keeps values in one `mppx_store` table (`expires` in milliseconds) and makes every write a single statement, as mppx's `Store.sql()` does, with `SQLStore.purge_expired()` to delete expired claims. Added the `postgres` extra (`asyncpg`) and exported `SQLStore` and `SQLDriver` from `mpp.stores`.
