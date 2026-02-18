---
pympp: patch
---

Moved `VerificationError` from `mpp.server.intent` to `mpp.errors` so that client-only imports no longer transitively load server dependencies. Added a re-export shim in `mpp.server.intent` for backwards compatibility and added import isolation tests to enforce the invariant.
