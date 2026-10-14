---
pympp: patch
---

Tempo `ChargeIntent` now logs a warning when no replay store is configured and it falls back to the default in-memory store. That store only provides per-process replay protection, so multi-worker, multi-replica, or restarting deployments should pass a shared store (e.g. `RedisStore`) via `Mpp.create(store=...)` or `ChargeIntent(store=...)`.
