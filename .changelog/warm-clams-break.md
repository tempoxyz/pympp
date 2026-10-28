---
pympp: minor
---

Added `PaymentMiddleware` ASGI middleware to `mpp.server.asgi` that gates HTTP requests behind a payment handler, returning a `402` challenge to unpaid clients and injecting `Payment-Receipt` headers into successful responses. Supports any ASGI-compatible framework and handles body binding, body replay, and non-HTTP scope pass-through.
