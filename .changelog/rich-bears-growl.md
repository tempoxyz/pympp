---
pympp: minor
---

Added `allowed_chain_ids` parameter to the `tempo()` factory and `TempoMethod` class, providing a client-side allowlist of chain IDs on which a charge may be paid. Challenges specifying a chain outside the allowlist are skipped during selection and rejected before signing; an empty sequence rejects all charges.
