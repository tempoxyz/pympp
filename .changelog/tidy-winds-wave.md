---
pympp: patch
---

Added a warning log to `ChargeIntent` when no replay store is configured and it falls back to the default in-memory store, alerting users that replay protection is limited to a single process and recommending a shared store (e.g. `RedisStore`) for multi-worker or multi-replica deployments.
