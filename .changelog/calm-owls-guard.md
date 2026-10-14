---
pympp: minor
---

Added client-side spend policy to the Tempo charge client. `max_atomic_amount` caps the challenge amount in base units, and `max_amount` caps it in token units using a required `max_amount_decimals`. Caps are parsed when the method is created, and a `max_amount` with more significant fractional digits than `max_amount_decimals` is rejected instead of rounded. Over-cap offers are skipped during challenge selection and rejected before signing. `expected_recipients` requires the primary recipient and every split recipient to be in an allowlist (case-insensitive), checked before signing.
