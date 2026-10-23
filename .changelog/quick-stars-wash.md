---
pympp: minor
---

Added `funding_currency` field to `Receipt` to report the token actually debited to fund a payment. For Tempo pull-mode charges, this reflects the DEX swap input token when an auto-swap route is used, or the charge currency for direct transfers. Updated parsing, formatting, and the `Receipt.success()` factory method to support the new field.
