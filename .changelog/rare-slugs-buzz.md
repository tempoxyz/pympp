---
pympp: minor
---

Added a `max_markers` parameter to the `credit` function and `credit_channel` to cap the number of live idempotency markers per channel, raising `RuntimeError` when the limit is reached while still allowing recorded keys to replay. Fixed the session client to accept credited close receipts where the final spend may be lower than previously acknowledged.
