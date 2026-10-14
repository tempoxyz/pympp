---
pympp: minor
---

Added `max_amount` and `expected_recipients` options to the Tempo charge client. `max_amount` caps the challenge amount in base units of the challenge currency, and `expected_recipients` requires the primary recipient and every split recipient to be in an allowlist (case-insensitive). Challenges that violate either policy are rejected before signing.
