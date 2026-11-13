---
pympp: patch
---

Fixed edge cases in Tempo ID DPoP proof validation and key set retry logic: lone surrogates in proof JTIs now return a malformed error instead of a store outage, replay store failures are now handled at the correct call site, the key set error is recorded before serving a stale set so the 30-second retry limit is preserved, and re-raised cached errors clear their traceback to prevent memory growth.
