---
pympp: minor
---

Added OpenAPI payment discovery module (`mpp.discovery`) with `generate`, `generate_proxy`, and `validate` functions and supporting route/issue types. Added Stripe Connect settlement support via new `ConnectSettlement` and `TransferData` types, wiring the optional `connect` parameter through `ChargeIntent.verify`, `SptPayments`, `TempoPayments`, and `record_crypto_payment`.
