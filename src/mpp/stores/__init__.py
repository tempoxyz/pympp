"""Concrete store backends for replay protection.

Available backends:

- ``MemoryStore`` – in-memory ``dict``, for development/testing.
- ``RedisStore`` – Redis/Valkey, for multi-instance production deployments.
- ``SQLiteStore`` – local SQLite file, for single-instance production deployments.
"""

from typing import TYPE_CHECKING, Any

from mpp.store import MemoryStore

if TYPE_CHECKING:
    from mpp.stores.redis import RedisStore
    from mpp.stores.sqlite import SQLiteStore

__all__ = ["MemoryStore", "RedisStore", "SQLiteStore"]


def __getattr__(name: str) -> Any:
    if name == "RedisStore":
        from mpp.stores.redis import RedisStore

        globals()[name] = RedisStore
        return RedisStore
    if name == "SQLiteStore":
        from mpp.stores.sqlite import SQLiteStore

        globals()[name] = SQLiteStore
        return SQLiteStore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
