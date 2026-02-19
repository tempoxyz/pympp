---
pympp: minor
---

Added full fee payer support to the Tempo method, allowing servers to co-sign sponsored transactions locally using a configured `fee_payer` account instead of forwarding to an external service. Updated the `tempo()` factory and `ChargeIntent` to propagate the fee payer account, and introduced expiring nonce logic for replay protection on sponsored transactions.
