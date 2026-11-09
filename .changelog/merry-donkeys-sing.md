---
pympp: minor
---

Added a `has_store` field to `ServerMethod` allowing `Mpp` to eagerly detect missing replay stores at construction time. Introduced a `_replay_store` module with `production_runtime()` and `check_fallback_allowed()` helpers that raise `RuntimeError` in production or multi-instance environments (AWS Lambda, Fly, Vercel, etc.) when a method would fall back to an in-memory store, matching the safety behavior of mppx.
