---
pympp: minor
---

Added client-side spend policy to the Tempo charge client. `max_atomic_amount` caps the challenge amount in base units, and `max_amount` caps it in token units using a required `max_amount_decimals`. Caps are validated when the method is created, and a `max_amount` with more significant fractional digits than `max_amount_decimals` is rejected instead of rounded. Caps require an explicit `currency=` or `currencies=` pin, and offers in any other currency are skipped and rejected. `expected_recipients` requires the primary recipient and every split recipient to be in an allowlist (case-insensitive). Offers outside the chain pin, caps or expected recipients are skipped during challenge selection and rejected before signing, using one shared check.
