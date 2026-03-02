---
pympp: patch
---

Fixed TLS enforcement on the client and server sides per spec §11. Added `allow_insecure` flag to `PaymentTransport` and `Client` to opt out for development, and added server-side expiry enforcement to reject replayed credentials after their challenge has expired.
