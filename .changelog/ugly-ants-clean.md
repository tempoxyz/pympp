---
pympp: minor
---

Added a Base USDC rail to Stripe machine payments: `deposit_addresses['base']` enables `payments.base.charge()` and `default_methods(base=...)`, recording Base charges in Stripe.
