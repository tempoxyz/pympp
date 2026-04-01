"""Concrete store backends for replay protection.

Available backends:

- ``MemoryStore`` – in-memory ``dict``, for development/testing.
- ``RedisStore`` – Redis/Valkey, for multi-instance production deployments.
- ``SQLiteStore`` – local SQLite file, for single-instance production deployments.
"""

from typing import Any

from mpp._lazy_exports import load_lazy_attr
from mpp.store import MemoryStore

_EXTRA_INSTALL_HINT = "Install the required store extra for this backend."

_LAZY_EXPORTS = {
    "mpp.stores.redis": ("RedisStore",),
    "mpp.stores.sqlite": ("SQLiteStore",),
}


def __getattr__(name: str) -> Any:
    return load_lazy_attr(__name__, name, _LAZY_EXPORTS, globals(), _EXTRA_INSTALL_HINT)
