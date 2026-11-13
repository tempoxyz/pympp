---
pympp: patch
---

Made `client_id` optional in `tempo.server.create` (defaults to `None`, accepting any app's tokens). Added `'dpop'` and `'tempo-id-token'` to `REQUEST_HEADERS`. Also limited serving a stale key set to one hour after it loaded, accepted extra spaces in the `Authorization` header, rejected requests as unavailable when the DPoP replay store fails, and made the client prover leave a Payment Credential already in `Authorization` in place.
