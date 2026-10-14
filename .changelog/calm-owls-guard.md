---
pympp: minor
---

Added client-side spend policy to the Tempo charge client. `max_atomic_amount` caps the challenge amount in base units, and `max_amount` caps it in token units using a required `max_amount_decimals`; a `max_amount` with more fractional digits than that is rejected instead of rounded. `expected_recipients` requires the primary recipient and every split recipient to be in an allowlist (case-insensitive). Challenges outside the policy are skipped during challenge selection, so an affordable offer is chosen, and rejected before signing.
