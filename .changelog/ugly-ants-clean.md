---
pympp: minor
---

Added `BasePayments` class and `base` deposit address support to Stripe machine payments, enabling Base USDC charges to be recorded in Stripe. Extended `MachinePayments.default_methods()` with an optional `base` keyword argument and updated `with_payment_intent_input` to correctly hide `payment_intent_options` from rail-level request resolution.
