---
pympp: patch
---

Added `sort_keys=True` to all `json.dumps()` calls to ensure JCS (RFC 8785) canonical JSON serialization when generating challenge IDs and credentials.
