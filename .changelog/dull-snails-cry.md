---
pympp: patch
---

Added `SQLStore`, an atomic key-value store on Postgres or SQLite with single-statement writes, as mppx's `Store.sql()` does. Added the `postgres` extra (`asyncpg`).
