# pyright: reportUnsupportedDunderAll=false

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

_LAZY_IMPORTS = {
    "RedisStore": "mpp.stores.redis",
    "SQLiteStore": "mpp.stores.sqlite",
}

__all__ = ["MemoryStore", *_LAZY_IMPORTS]


def __getattr__(name: str) -> Any:
    return load_lazy_attr(__name__, name, _LAZY_IMPORTS, globals(), _EXTRA_INSTALL_HINT)
