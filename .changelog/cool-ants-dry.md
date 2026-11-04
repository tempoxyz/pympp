---
pympp: minor
---

Added `http_client` parameter to the `charge` function and `TempoMethod` class, allowing callers to supply a custom `httpx.AsyncClient` for all RPC calls (e.g., to set a Tempo API key via request headers).
