---
pympp: patch
---

Fixed initial requests to advertise supported payment methods via the `Accept-Payment` header, derived from the configured payment methods and their intents. Existing `Accept-Payment` headers are preserved when explicitly set by the caller.
