"""Concrete store backends for replay protection.

Available backends:

- ``MemoryStore`` – in-memory ``dict``, for development/testing.
- ``RedisStore`` – Redis/Valkey, for multi-instance production deployments.
- ``SQLiteStore`` – local SQLite file, for single-instance production deployments.
"""

from mpp.store import MemoryStore

__all__ = ["MemoryStore", "RedisStore", "SQLiteStore"]


def __getattr__(name: str):  # type: ignore[reportReturnType]
    if name == "RedisStore":
        from mpp.stores.redis import RedisStore

        return RedisStore
    if name == "SQLiteStore":
        from mpp.stores.sqlite import SQLiteStore

        return SQLiteStore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
