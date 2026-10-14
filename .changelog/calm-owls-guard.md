---
pympp: minor
---

Added client-side spend policy to the Tempo charge client. `max_atomic_amount` caps the challenge amount in base units, and `max_amount` caps it in token units, using the decimals of built-in currencies or an explicit `decimals` and rejecting other currencies. `expected_recipients` requires the primary recipient and every split recipient to be in an allowlist (case-insensitive). Challenges that violate any policy are rejected before signing.
