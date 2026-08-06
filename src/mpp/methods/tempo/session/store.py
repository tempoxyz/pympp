"""Memory and durable SQLite storage for Tempo session channels."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from .models import SessionRecord


class SessionStore(Protocol):
    """Durable record contract used by :class:`TempoSessionManager`."""

    async def get(self, scope: str) -> SessionRecord | None: ...

    async def get_by_channel(self, channel_id: str) -> SessionRecord | None: ...

    async def save(self, record: SessionRecord) -> None: ...

    async def delete(self, scope: str) -> None: ...

    async def list(self) -> list[SessionRecord]: ...


class MemorySessionStore:
    """Process-local session store suitable for tests and short-lived clients."""

    def __init__(self, records: Iterable[SessionRecord] = ()) -> None:
        self._lock = threading.RLock()
        self._records = {record.scope: record.to_dict() for record in records}

    async def get(self, scope: str) -> SessionRecord | None:
        with self._lock:
            value = self._records.get(scope)
            return None if value is None else SessionRecord.from_dict(value)

    async def get_by_channel(self, channel_id: str) -> SessionRecord | None:
        normalized = channel_id.lower()
        with self._lock:
            for value in self._records.values():
                if value["channel_id"].lower() == normalized:
                    return SessionRecord.from_dict(value)
        return None

    async def save(self, record: SessionRecord) -> None:
        with self._lock:
            self._records[record.scope] = record.to_dict()

    async def delete(self, scope: str) -> None:
        with self._lock:
            self._records.pop(scope, None)

    async def list(self) -> list[SessionRecord]:
        with self._lock:
            return [
                SessionRecord.from_dict(value)
                for _, value in sorted(self._records.items(), key=lambda item: item[0])
            ]


class SQLiteSessionStore:
    """Thread-safe SQLite session journal usable from sync and async HTTPX clients.

    Each save writes the channel state and its pending signed operation in one
    transaction. A newly constructed store can therefore resume the exact
    operation after process restart without minting a second transaction or a
    higher voucher.
    """

    def __init__(self, path: str | Path) -> None:
        resolved = Path(path).expanduser()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self.path = str(resolved)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._db.execute("PRAGMA busy_timeout=30000")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS tempo_sessions ("
            " scope TEXT PRIMARY KEY,"
            " channel_id TEXT NOT NULL UNIQUE,"
            " record TEXT NOT NULL"
            ")"
        )
        self._db.commit()

    async def get(self, scope: str) -> SessionRecord | None:
        with self._lock:
            row = self._db.execute(
                "SELECT record FROM tempo_sessions WHERE scope = ?", (scope,)
            ).fetchone()
        return None if row is None else SessionRecord.from_dict(json.loads(row[0]))

    async def get_by_channel(self, channel_id: str) -> SessionRecord | None:
        with self._lock:
            row = self._db.execute(
                "SELECT record FROM tempo_sessions WHERE lower(channel_id) = lower(?)",
                (channel_id,),
            ).fetchone()
        return None if row is None else SessionRecord.from_dict(json.loads(row[0]))

    async def save(self, record: SessionRecord) -> None:
        value = json.dumps(record.to_dict(), separators=(",", ":"), sort_keys=True)
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO tempo_sessions (scope, channel_id, record) VALUES (?, ?, ?)"
                " ON CONFLICT(scope) DO UPDATE SET"
                " channel_id = excluded.channel_id, record = excluded.record",
                (record.scope, record.channel_id, value),
            )

    async def delete(self, scope: str) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM tempo_sessions WHERE scope = ?", (scope,))

    async def list(self) -> list[SessionRecord]:
        with self._lock:
            rows = self._db.execute("SELECT record FROM tempo_sessions ORDER BY scope").fetchall()
        return [SessionRecord.from_dict(json.loads(row[0])) for row in rows]

    def close(self) -> None:
        """Close the local SQLite connection."""

        with self._lock:
            self._db.close()

    def __enter__(self) -> SQLiteSessionStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
