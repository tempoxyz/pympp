"""Tests for SQLStore on SQLite, and on Postgres when POSTGRES_URL is set.

Mirrors mppx src/Store.test.ts (Store.sql) and src/Store.postgres.test.ts. Run Postgres with:
    POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres uv run pytest -m postgres
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import time
import uuid
from collections.abc import Sequence
from typing import Any

import pytest

from mpp.store import CompareAndSetStore, ExpiringStore
from mpp.stores.sql import SQLDialect, SQLStore

POSTGRES_URL = os.environ.get("POSTGRES_URL")


class Clock:
    """Shifts time.time, which the store passes to SQL as the current time."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.offset = 0.0
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + self.offset)

    def advance(self, seconds: float) -> None:
        self.offset += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    return Clock(monkeypatch)


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgres",
            marks=[
                pytest.mark.postgres,
                pytest.mark.skipif(
                    not POSTGRES_URL, reason="POSTGRES_URL not set (no Postgres instance)"
                ),
            ],
        ),
    ]
)
async def database(request: pytest.FixtureRequest, tmp_path):
    """Yields (make_store, run_sql) over a fresh table name per test."""
    table = f"mppx_store_{uuid.uuid4().hex[:8]}"
    if request.param == "sqlite":
        import aiosqlite

        db = await aiosqlite.connect(str(tmp_path / "sql.db"))

        def make(**kwargs: Any) -> SQLStore:
            return SQLStore.sqlite(db, **{"table": table, **kwargs})

        async def run(sql: str) -> None:
            await db.execute(sql)
            await db.commit()

        yield make, run
        await db.close()
    else:
        import asyncpg

        pool = await asyncpg.create_pool(POSTGRES_URL, min_size=1, max_size=10)

        def make(**kwargs: Any) -> SQLStore:
            return SQLStore.postgres(pool, **{"table": table, **kwargs})

        async def run(sql: str) -> None:
            await pool.execute(sql)

        yield make, run
        for name in (table, f"public.{table}_custom", f"{table}_premade"):
            await pool.execute(f"DROP TABLE IF EXISTS {name}")
        await pool.close()


@pytest.fixture
def store(database) -> SQLStore:
    return database[0]()


class TestKeyValue:
    async def test_implements_atomic_protocols(self, store: SQLStore) -> None:
        assert isinstance(store, ExpiringStore)
        assert isinstance(store, CompareAndSetStore)

    async def test_get_put_delete(self, store: SQLStore) -> None:
        assert await store.get("k") is None
        await store.put("k", '{"n":1}')
        assert await store.get("k") == '{"n":1}'
        await store.put("k", '{"n":2}')
        assert await store.get("k") == '{"n":2}'
        await store.delete("k")
        assert await store.get("k") is None

    async def test_put_if_absent(self, store: SQLStore) -> None:
        assert await store.put_if_absent("k", "first") is True
        assert await store.put_if_absent("k", "second") is False
        assert await store.get("k") == "first"

    async def test_instances_share_the_table(self, database) -> None:
        make, _ = database
        first, second = make(), make()
        assert await first.put_if_absent("k", "v")
        assert await second.get("k") == "v"


class TestCompareAndSet:
    async def test_swaps_matching_value(self, store: SQLStore) -> None:
        await store.put("k", "a")
        assert await store.compare_and_set("k", "a", "b") is True
        assert await store.get("k") == "b"

    async def test_refuses_on_conflict(self, store: SQLStore) -> None:
        await store.put("k", "a")
        assert await store.compare_and_set("k", "stale", "b") is False
        assert await store.get("k") == "a"

    async def test_inserts_absent_key(self, store: SQLStore) -> None:
        assert await store.compare_and_set("k", None, "a") is True
        assert await store.compare_and_set("k", None, "b") is False
        assert await store.get("k") == "a"

    async def test_refuses_when_expected_key_is_absent(self, store: SQLStore) -> None:
        assert await store.compare_and_set("k", "a", "b") is False
        assert await store.get("k") is None

    async def test_deletes_matching_value(self, store: SQLStore) -> None:
        await store.put("k", "a")
        assert await store.compare_and_set("k", "stale", None) is False
        assert await store.get("k") == "a"
        assert await store.compare_and_set("k", "a", None) is True
        assert await store.get("k") is None

    async def test_absent_to_absent_reports_absence(self, store: SQLStore) -> None:
        assert await store.compare_and_set("k", None, None) is True
        await store.put("k", "a")
        assert await store.compare_and_set("k", None, None) is False

    async def test_keeps_expiry_and_ignores_expired_rows(
        self, store: SQLStore, clock: Clock
    ) -> None:
        assert await store.put_if_absent_until("k", "a", time.time() + 10)
        assert await store.compare_and_set("k", "a", "b") is True
        clock.advance(11)
        assert await store.get("k") is None
        assert await store.compare_and_set("k", "b", "c") is False
        assert await store.compare_and_set("k", "b", None) is False
        assert await store.compare_and_set("k", None, None) is True
        assert await store.compare_and_set("k", None, "fresh") is True
        clock.advance(3600)
        assert await store.get("k") == "fresh"

    async def test_concurrent_swaps_have_one_winner(self, store: SQLStore) -> None:
        await store.put("k", "start")
        results = await asyncio.gather(
            *(store.compare_and_set("k", "start", str(i)) for i in range(20))
        )
        assert results.count(True) == 1
        assert await store.get("k") == str(results.index(True))

    async def test_concurrent_writes_from_stores_sharing_a_connection(self, database) -> None:
        make, _ = database
        first, second = make(), make()
        await first.get("warm")
        results = await asyncio.gather(
            *(
                (first if i % 2 else second).compare_and_set(f"k{i}", None, str(i))
                for i in range(50)
            ),
            *((first if i % 2 else second).put(f"p{i}", str(i)) for i in range(50)),
        )
        assert all(r in (True, None) for r in results)
        assert [await first.get(f"k{i}") for i in range(50)] == [str(i) for i in range(50)]
        assert [await second.get(f"p{i}") for i in range(50)] == [str(i) for i in range(50)]


class TestExpiringClaim:
    async def test_refused_before_expiry_reused_after(self, store: SQLStore, clock: Clock) -> None:
        assert await store.put_if_absent_until("claim", "first", time.time() + 10) is True
        assert await store.put_if_absent_until("claim", "second", time.time() + 10) is False
        assert await store.put_if_absent("claim", "third") is False
        assert await store.get("claim") == "first"
        clock.advance(11)
        assert await store.get("claim") is None
        assert await store.put_if_absent_until("claim", "second", time.time() + 10) is True
        assert await store.get("claim") == "second"

    async def test_never_replaces_a_persistent_key(self, store: SQLStore, clock: Clock) -> None:
        await store.put("k", "persistent")
        assert await store.put_if_absent_until("k", "temp", time.time() + 10) is False
        clock.advance(3600)
        assert await store.put_if_absent_until("k", "temp", time.time() + 10) is False
        assert await store.get("k") == "persistent"

    async def test_rejects_invalid_deadlines(self, store: SQLStore) -> None:
        for deadline in (time.time() - 1, float("nan"), float("inf")):
            with pytest.raises(ValueError, match="finite future"):
                await store.put_if_absent_until("k", "v", deadline)
        assert await store.get("k") is None

    async def test_concurrent_claims_have_one_winner(self, store: SQLStore) -> None:
        deadline = time.time() + 60
        results = await asyncio.gather(
            *(store.put_if_absent_until("claim", str(i), deadline) for i in range(20))
        )
        assert results.count(True) == 1
        assert await store.get("claim") == str(results.index(True))

    async def test_concurrent_claims_of_an_expired_row_have_one_winner(
        self, store: SQLStore, clock: Clock
    ) -> None:
        assert await store.put_if_absent_until("claim", "old", time.time() + 10)
        clock.advance(11)
        deadline = time.time() + 60
        results = await asyncio.gather(
            *(store.put_if_absent_until("claim", str(i), deadline) for i in range(20))
        )
        assert results.count(True) == 1
        assert await store.get("claim") == str(results.index(True))


class TestPurgeExpired:
    async def test_deletes_only_expired_claims(self, store: SQLStore, clock: Clock) -> None:
        await store.put("permanent", "1")
        assert await store.put_if_absent("forever", "2")
        assert await store.put_if_absent_until("short", "3", time.time() + 10)
        assert await store.put_if_absent_until("live", "4", time.time() + 100)
        assert await store.purge_expired() == 0
        clock.advance(11)
        assert await store.purge_expired() == 1
        assert await store.get("permanent") == "1"
        assert await store.get("forever") == "2"
        assert await store.get("live") == "4"
        assert await store.purge_expired() == 0

    async def test_stores_expiry_in_milliseconds(self, database) -> None:
        make, _ = database
        store = make()
        deadline = time.time() + 60
        assert await store.put_if_absent_until("claim", "v", deadline)
        rows = await store._query(  # pyright: ignore[reportPrivateUsage]
            f"SELECT expires FROM {store._table} WHERE key = ?",  # pyright: ignore[reportPrivateUsage]
            ["claim"],
        )
        assert rows[0][0] == pytest.approx(deadline * 1000)


class TestTable:
    @pytest.mark.parametrize(
        "table", ["", "1abc", "store; DROP TABLE x", "a.b.c", "a-b", "a.", "my table"]
    )
    def test_rejects_invalid_table_names(self, table: str) -> None:
        with pytest.raises(ValueError, match="Invalid SQL store table name"):
            SQLStore.sqlite(object(), table=table)

    async def test_custom_schema_qualified_table(self, database) -> None:
        make, _ = database
        table = make()._table + "_custom"
        schema = "public" if make()._driver.dialect == "postgres" else "main"
        custom = make(table=f"{schema}.{table}")
        default = make()
        await custom.put("k", "custom")
        assert await custom.get("k") == "custom"
        assert await default.get("k") is None

    async def test_create_table_false_uses_an_existing_table(self, database) -> None:
        make, run = database
        table = make()._table + "_premade"
        missing = make(table=table, create_table=False)
        with pytest.raises(Exception):  # noqa: B017 - the driver's own error
            await missing.get("k")
        await run(
            f"CREATE TABLE {table} "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL, expires DOUBLE PRECISION)"
        )
        assert await missing.put_if_absent("k", "v")
        assert await missing.get("k") == "v"


class FakeDriver:
    """Records statements; optionally fails CREATE TABLE and the probe."""

    def __init__(
        self, dialect: SQLDialect = "sqlite", *, fail_create: bool = False, probe_ok: bool = True
    ) -> None:
        self.dialect: SQLDialect = dialect
        self.fail_create = fail_create
        self.probe_ok = probe_ok
        self.statements: list[tuple[str, Sequence[Any]]] = []

    async def query(self, sql: str, params: Sequence[Any]) -> Sequence[Sequence[Any]]:
        self.statements.append((sql, params))
        if sql.startswith("CREATE") and self.fail_create:
            raise RuntimeError("duplicate key value violates unique constraint")
        if sql.startswith("SELECT 1") and not self.probe_ok:
            raise RuntimeError("relation does not exist")
        return []


class TestDriver:
    async def test_creates_the_table_once(self) -> None:
        driver = FakeDriver()
        store = SQLStore(driver)
        await asyncio.gather(store.get("a"), store.get("b"), store.put("c", "v"))
        creates = [sql for sql, _ in driver.statements if sql.startswith("CREATE")]
        assert creates == [
            "CREATE TABLE IF NOT EXISTS mppx_store "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL, expires DOUBLE PRECISION)"
        ]

    async def test_tolerates_a_concurrent_create_when_the_table_exists(self) -> None:
        driver = FakeDriver(fail_create=True)
        store = SQLStore(driver)
        assert await store.get("k") is None
        assert await store.get("k") is None
        assert sum(sql.startswith("CREATE") for sql, _ in driver.statements) == 1

    async def test_raises_and_retries_when_create_fails(self) -> None:
        driver = FakeDriver(fail_create=True, probe_ok=False)
        store = SQLStore(driver)
        with pytest.raises(RuntimeError, match="duplicate key"):
            await store.get("k")
        driver.fail_create = False
        assert await store.get("k") is None

    async def test_postgres_numbers_placeholders(self) -> None:
        driver = FakeDriver("postgres")
        store = SQLStore(driver, create_table=False)
        await store.compare_and_set("k", "a", "b")
        sql, params = driver.statements[-1]
        assert "?" not in sql
        assert "value = $1 WHERE key = $2 AND value = $3" in sql
        assert "expires > $4" in sql
        assert params[:3] == ["b", "k", "a"]

    async def test_postgres_adapter_calls_fetch(self) -> None:
        calls: list[tuple[Any, ...]] = []

        class Client:
            async def fetch(self, sql: str, *args: Any) -> list[tuple[Any, ...]]:
                calls.append((sql, *args))
                return [("k",)]

        store = SQLStore.postgres(Client(), table="s.t", create_table=False)
        assert await store.put_if_absent("k", "v") is True
        sql, *args = calls[0]
        assert sql.startswith(
            "INSERT INTO s.t AS existing (key, value, expires) VALUES ($1, $2, $3)"
        )
        assert args[:3] == ["k", "v", None]

    async def test_sqlite_rolls_back_a_failed_statement(self) -> None:
        import aiosqlite

        async with aiosqlite.connect(":memory:") as db:
            store = SQLStore.sqlite(db)
            await store.put("k", "v")
            with pytest.raises(sqlite3.IntegrityError):
                await store._driver.query(  # pyright: ignore[reportPrivateUsage]
                    "INSERT INTO mppx_store (key, value) VALUES (?, NULL)", ["x"]
                )
            assert not db.in_transaction
            assert await store.get("k") == "v"

    def test_lazy_export(self) -> None:
        import mpp.stores

        assert mpp.stores.SQLStore is SQLStore
