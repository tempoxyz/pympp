---
pympp: minor
---

Added a transport-neutral `PaymentRuntime` class that provides reusable primitives for matching payment challenges and creating credentials without depending on HTTPX. Refactored `PaymentTransport` and `Client` to accept either a `methods` list or a pre-built `runtime` instance, and consolidated the `Method` protocol into `mpp.runtime`.
