---
pympp: patch
---

Tempo `ChargeIntent` now logs a one-time (per process) warning when no replay store is configured and it falls back to an in-memory store. Replay protection backed by that store only covers the current process, so multi-worker, multi-replica, or restarting deployments should pass a shared store (e.g. `RedisStore`) via `Mpp.create(store=...)` or `ChargeIntent(store=...)`.
