---
pympp: minor
---

Added client and server payment lifecycle hooks (`EventDispatcher`, `PaymentEvent`) for observing challenge selection, credential creation, payment responses, successes, and failures. Both `PaymentTransport`/`Client` and `Mpp`/`pay` now expose typed `on_*` registration methods with unsubscribe callbacks.
