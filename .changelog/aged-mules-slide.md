---
pympp: patch
---

Added optional `allowed_origins` parameter to `Client` and `PaymentTransport` to restrict automatic payments to approved HTTP(S) origins before credential creation. An empty list denies all payments; omitting the parameter preserves existing behavior of allowing payments to any directly requested origin.
