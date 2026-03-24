"""SQLite-backed store for single-instance production deployments.

Uses ``aiosqlite`` for async access to Python's built-in ``sqlite3``.
Install with::

    pip install pympp[sqlite]

Example::

    from mpp.stores import SQLiteStore

    store = await SQLiteStore.create("mpp.db")
"""

from __future__ import annotations

import time
from typing import Any


class SQLiteStore:
    """Async key-value store backed by a local SQLite file.

    Keys are stored in a ``kv`` table with optional TTL.  Expired rows
    are lazily pruned on ``get`` and ``put_if_absent``.

    ``put_if_absent`` uses ``INSERT OR IGNORE`` — a single atomic SQL
    statement with no TOCTOU race.
    """

    def __init__(
        self,
        db: Any,
        *,
        ttl_seconds: int = 300,
    ) -> None:
        self._db = db
        self._ttl = ttl_seconds

    @classmethod
    async def create(
        cls,
        path: str = "mpp.db",
        *,
        ttl_seconds: int = 300,
    ) -> SQLiteStore:
        """Open (or create) a SQLite database and initialize the schema.

        Args:
            path: Filesystem path for the database file.
                Use ``":memory:"`` for an ephemeral in-memory database.
            ttl_seconds: Seconds before a key expires (default 300).
        """
        import aiosqlite

        db = await aiosqlite.connect(path)
        await db.execute(
            "CREATE TABLE IF NOT EXISTS kv ("
            "  key TEXT PRIMARY KEY,"
            "  value TEXT NOT NULL,"
            "  expires_at REAL NOT NULL"
            ")"
        )
        await db.commit()
        return cls(db, ttl_seconds=ttl_seconds)

    async def close(self) -> None:
        """Close the underlying database connection."""
        await self._db.close()

    async def __aenter__(self) -> SQLiteStore:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _expires_at(self) -> float:
        return time.time() + self._ttl

    async def get(self, key: str) -> Any | None:
        now = time.time()
        cursor = await self._db.execute(
            "SELECT value FROM kv WHERE key = ? AND expires_at > ?",
            (key, now),
        )
        row = await cursor.fetchone()
        return row[0] if row else None

    async def put(self, key: str, value: Any) -> None:
        await self._db.execute(
            "INSERT INTO kv (key, value, expires_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
            " expires_at = excluded.expires_at",
            (key, value, self._expires_at()),
        )
        await self._db.commit()

    async def delete(self, key: str) -> None:
        await self._db.execute("DELETE FROM kv WHERE key = ?", (key,))
        await self._db.commit()

    async def put_if_absent(self, key: str, value: Any) -> bool:
        """Atomic conditional insert.

        Deletes any expired row for *key* first, then uses
        ``INSERT OR IGNORE`` so the write only succeeds when the
        key does not already exist.

        Returns ``True`` if the key was new, ``False`` if it existed.
        """
        now = time.time()
        await self._db.execute(
            "DELETE FROM kv WHERE key = ? AND expires_at <= ?", (key, now)
        )
        cursor = await self._db.execute(
            "INSERT OR IGNORE INTO kv (key, value, expires_at) VALUES (?, ?, ?)",
            (key, value, self._expires_at()),
        )
        await self._db.commit()
        return cursor.rowcount > 0
