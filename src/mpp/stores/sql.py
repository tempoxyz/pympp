"""Atomic SQL-backed store for Postgres and SQLite.

Values live as text in one table (``mppx_store`` by default, created on first use) with
an ``expires`` column for temporary claims. Every write is a single statement, so it
needs no interactive transactions, only ``ON CONFLICT`` and ``RETURNING`` (Postgres,
SQLite 3.35+). The table has the layout of mppx's ``Store.sql()``, with ``expires`` in
milliseconds since the Unix epoch, but values are stored as given rather than in mppx's
JSON envelopes, so give a pympp server its own table rather than sharing one with mppx.

Use :meth:`SQLStore.postgres` with an ``asyncpg`` pool (``pip install pympp[postgres]``),
:meth:`SQLStore.sqlite` with an ``aiosqlite`` connection (``pip install pympp[sqlite]``),
or pass any :class:`SQLDriver`.

Example::

    import asyncpg
    from mpp.stores import SQLStore

    store = SQLStore.postgres(await asyncpg.create_pool(DATABASE_URL))
"""

from __future__ import annotations

import asyncio
import re
import time
import weakref
from collections.abc import Sequence
from typing import Any, Literal, Protocol

from mpp.store import _validate_expiry

SQLDialect = Literal["postgres", "sqlite"]
"""Placeholder style: Postgres numbers them (``$1``), SQLite uses ``?``."""

_TABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?")


class SQLDriver(Protocol):
    """Runs one statement with positional parameters and returns its rows."""

    @property
    def dialect(self) -> SQLDialect:
        """Placeholder style of :meth:`query`'s statements."""
        ...

    async def query(self, sql: str, params: Sequence[Any]) -> Sequence[Sequence[Any]]:
        """Run *sql* (with ``?`` or ``$N`` placeholders, per :attr:`dialect`) and return rows."""
        ...


class _PostgresDriver:
    dialect: SQLDialect = "postgres"

    def __init__(self, client: Any) -> None:
        self._client = client

    async def query(self, sql: str, params: Sequence[Any]) -> Sequence[Sequence[Any]]:
        return await self._client.fetch(sql, *params)


# One lock per aiosqlite connection, shared by every store on it: a statement started
# between a write's cursor close and its commit makes that commit fail with "SQL statements
# in progress" although the write already happened.
_SQLITE_LOCKS: weakref.WeakKeyDictionary[Any, asyncio.Lock] = weakref.WeakKeyDictionary()


class _SQLiteDriver:
    dialect: SQLDialect = "sqlite"

    def __init__(self, db: Any) -> None:
        self._db = db
        try:
            self._lock = _SQLITE_LOCKS.setdefault(db, asyncio.Lock())
        except TypeError:  # not weak-referenceable: lock this driver's own statements
            self._lock = asyncio.Lock()

    async def query(self, sql: str, params: Sequence[Any]) -> Sequence[Sequence[Any]]:
        async with self._lock:
            try:
                async with self._db.execute(sql, tuple(params)) as cursor:
                    rows = await cursor.fetchall()
                await self._db.commit()
            except BaseException:
                # sqlite3 opened a transaction before a write: never leave it holding locks.
                await self._db.rollback()
                raise
            return rows


class SQLStore:
    """Atomic key-value store on a SQL database, shared by every process using the table.

    Implements :class:`~mpp.store.ExpiringStore` and :class:`~mpp.store.CompareAndSetStore`.
    Keys written by ``put``, ``put_if_absent`` and ``compare_and_set`` never expire;
    ``put_if_absent_until`` claims expire at their deadline, after which ``get`` reports
    them missing and the next claim replaces them in the same statement. Expired rows stay
    in the table until a write to the same key replaces them or :meth:`purge_expired`
    deletes them.

    Args:
        driver: Runs the statements; see :meth:`postgres` and :meth:`sqlite`.
        table: Table holding the values, optionally schema-qualified.
        create_table: Create the table on first use (``CREATE TABLE IF NOT EXISTS``).
            Set ``False`` when migrations create it.

    Raises:
        ValueError: If *table* is not a plain or schema-qualified SQL identifier.
    """

    def __init__(
        self,
        driver: SQLDriver,
        *,
        table: str = "mppx_store",
        create_table: bool = True,
    ) -> None:
        if not _TABLE_NAME.fullmatch(table):
            raise ValueError(f'Invalid SQL store table name: "{table}".')
        self._driver = driver
        self._table = table
        self._ready = not create_table
        self._lock = asyncio.Lock()

    @classmethod
    def postgres(
        cls, client: Any, *, table: str = "mppx_store", create_table: bool = True
    ) -> SQLStore:
        """Store on an ``asyncpg`` pool or connection (anything with ``fetch(sql, *args)``).

        Use a pool when requests run concurrently: one connection runs one query at a time.
        """
        return cls(_PostgresDriver(client), table=table, create_table=create_table)

    @classmethod
    def sqlite(cls, db: Any, *, table: str = "mppx_store", create_table: bool = True) -> SQLStore:
        """Store on an ``aiosqlite`` connection; each statement commits on its own."""
        return cls(_SQLiteDriver(db), table=table, create_table=create_table)

    async def _ensure_table(self) -> None:
        if self._ready:
            return
        async with self._lock:
            if self._ready:
                return
            try:
                await self._driver.query(
                    f"CREATE TABLE IF NOT EXISTS {self._table} "
                    "(key TEXT PRIMARY KEY, value TEXT NOT NULL, expires DOUBLE PRECISION)",
                    [],
                )
            except Exception:
                # Concurrent CREATE TABLE IF NOT EXISTS from other processes can fail on
                # Postgres (duplicate catalog row) although the table now exists: probe it.
                try:
                    await self._driver.query(f"SELECT 1 FROM {self._table} WHERE 1 = 0", [])
                except Exception:
                    pass
                else:
                    self._ready = True
                    return
                raise
            self._ready = True

    async def _query(self, sql: str, params: Sequence[Any]) -> Sequence[Sequence[Any]]:
        await self._ensure_table()
        if self._driver.dialect == "postgres":
            counter = iter(range(1, len(params) + 1))
            sql = re.sub(r"\?", lambda _: f"${next(counter)}", sql)
        return await self._driver.query(sql, params)

    async def purge_expired(self) -> int:
        """Delete rows whose expiry has passed and return how many were removed.

        Replay keys are rarely written twice, so expired claims are not replaced in place;
        call this periodically (for example from a background task) to bound the table.
        Rows without an expiry and live claims are never touched.
        """
        rows = await self._query(
            f"DELETE FROM {self._table} WHERE expires IS NOT NULL AND expires <= ? RETURNING key",
            [_now_ms()],
        )
        return len(rows)

    async def get(self, key: str) -> Any | None:
        rows = await self._query(
            f"SELECT value FROM {self._table} WHERE key = ? AND (expires IS NULL OR expires > ?)",
            [key, _now_ms()],
        )
        return rows[0][0] if rows else None

    async def put(self, key: str, value: Any) -> None:
        await self._query(
            f"INSERT INTO {self._table} (key, value, expires) VALUES (?, ?, NULL) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value, expires = NULL",
            [key, value],
        )

    async def delete(self, key: str) -> None:
        await self._query(f"DELETE FROM {self._table} WHERE key = ?", [key])

    async def put_if_absent(self, key: str, value: Any) -> bool:
        """Atomic insert of a claim that never expires, replacing only an expired row."""
        return await self._claim(key, value, None)

    async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
        """Atomic insert expiring at *expires_at*, replacing only an expired row."""
        _validate_expiry(expires_at)
        # The claim's own deadline may have passed while the statement ran.
        claimed = await self._claim(key, value, expires_at * 1000)
        return claimed and expires_at > time.time()

    async def compare_and_set(self, key: str, expected: Any | None, value: Any | None) -> bool:
        """Atomic conditional write: one statement keyed on the current live value."""
        now = _now_ms()
        if expected is None:
            if value is None:
                return await self.get(key) is None
            return await self._claim(key, value, None)
        if value is None:
            rows = await self._query(
                f"DELETE FROM {self._table} WHERE key = ? AND value = ? "
                "AND (expires IS NULL OR expires > ?) RETURNING key",
                [key, expected, now],
            )
        else:
            rows = await self._query(
                f"UPDATE {self._table} SET value = ? WHERE key = ? AND value = ? "
                "AND (expires IS NULL OR expires > ?) RETURNING key",
                [value, key, expected, now],
            )
        return len(rows) > 0

    async def _claim(self, key: str, value: Any, expires_at: float | None) -> bool:
        # One statement: insert the row, or replace one whose expiry has passed.
        rows = await self._query(
            f"INSERT INTO {self._table} AS existing (key, value, expires) VALUES (?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value, expires = excluded.expires "
            "WHERE existing.expires IS NOT NULL AND existing.expires <= ? RETURNING key",
            [key, value, expires_at, _now_ms()],
        )
        return len(rows) > 0


def _now_ms() -> float:
    """The current time in milliseconds since the Unix epoch, the unit of ``expires``."""
    return time.time() * 1000
