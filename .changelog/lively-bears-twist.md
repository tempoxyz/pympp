---
pympp: minor
---

Made `client_id` optional in `TempoId.create` (defaults to `None`, accepting any app's tokens). Added `'dpop'` and `'tempo-id-token'` to `REQUEST_HEADERS`. Also fixed key set staleness to expire after one hour, improved `Authorization` header parsing, and added a `TypeError` guard in the client prover when a Payment credential is already in `Authorization`.
