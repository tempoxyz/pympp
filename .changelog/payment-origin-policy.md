---
pympp: patch
---

Added optional `allowed_origins` to `Client` and `PaymentTransport` to reject automatic payments outside configured HTTP(S) origins before credential creation. Origin matching includes scheme and port and preserves arbitrary challenge realms. An empty list denies all payments; omitting the option preserves existing behavior. Use alongside method amount and recipient limits.
