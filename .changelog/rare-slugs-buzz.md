---
pympp: patch
---

Added a `max_markers` parameter (default 1024) to `credit` and `credit_channel` that caps a channel's live credit idempotency markers, raising `RuntimeError` for a new key at the cap while recorded keys still replay. Fixed the session client to accept a close receipt whose final spend credits lowered, and `SessionManager.spent` now reports that final spend.
