---
pympp: minor
---

Require explicit server secret key — remove implicit `.env` auto-generation/persistence. `MPP_SECRET_KEY` must be set in the environment or `secret_key` passed explicitly; whitespace-only values are rejected. Preserves `__wrapped__` on payment decorators. Aligns pympp with mpp-rs and mppx behavior.
