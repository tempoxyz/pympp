---
pympp: minor
---

Added `opaque`/`meta` field support for server-defined correlation data in challenges. The `meta` parameter on `Challenge.create()` and `verify_or_challenge()` stores arbitrary string key-value pairs as an HMAC-bound `opaque` field, included in challenge IDs and serialized in `WWW-Authenticate` and `Authorization` headers.
