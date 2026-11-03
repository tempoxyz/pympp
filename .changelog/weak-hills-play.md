---
pympp: minor
---

Added client-side spending policy options (`currencies`, `expected_recipients`, `max_atomic_amount`, `max_amount`, `max_amount_decimals`) to the `session()` function and `SessionMethod` for Tempo session payments. These new optional parameters allow filtering and rejecting session offers based on currency, recipient, and per-unit amount, while explicit channel closes bypass the policy.
