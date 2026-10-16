---
pympp: minor
---

Bind MCP challenges to their receiving tool. Low-level `create_challenge` and `verify_or_challenge` now require `tool`; `pay` derives a stable handler identity unless explicitly configured. Outstanding unscoped challenges must be reissued. Return a terminal 403 for already-succeeded Stripe payments. Preserve caller-supplied payment credentials and prevent redirects after payment from initiating another payment. Index SQLite expiry cleanup for existing and new stores.
