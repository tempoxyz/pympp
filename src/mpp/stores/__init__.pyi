from mpp.store import MemoryStore as _MemoryStore
from mpp.stores.redis import RedisStore as _RedisStore
from mpp.stores.sql import SQLDriver as _SQLDriver
from mpp.stores.sql import SQLStore as _SQLStore
from mpp.stores.sqlite import SQLiteStore as _SQLiteStore

MemoryStore = _MemoryStore
RedisStore = _RedisStore
SQLiteStore = _SQLiteStore
SQLDriver = _SQLDriver
SQLStore = _SQLStore
