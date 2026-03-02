---
pympp: minor
---

Added `digest` and `opaque` fields to `MCPChallenge` for extended challenge metadata propagation. Fixed deterministic body digest computation by adding `sort_keys=True` to JSON serialization, and corrected ISO 8601 timestamp formatting. Added cross-realm attack prevention by validating echoed challenge fields (`realm`, `method`, `intent`) against server-expected values.
