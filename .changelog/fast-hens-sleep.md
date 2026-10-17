---
pympp: minor
---

Bound MCP challenges to their receiving tool via a new required `tool` parameter on `create_challenge` and `verify_or_challenge`; the `@pay` decorator derives a stable identity from the handler's module and qualified name unless explicitly overridden. Prevented HTTP clients from retrying payments when caller-supplied credentials are present and blocked post-redirect payment initiation. Returned a terminal 403 for already-succeeded Stripe payments and added an index on SQLite expiry for faster cleanup.
