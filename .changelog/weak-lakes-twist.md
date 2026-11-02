---
pympp: patch
---

Persisted server close transaction expiry (`pending_close_valid_before`) separately from payer close-request timestamps so that a cancelled payer close cannot reopen spending while an earlier server-signed close transaction may still settle on-chain.
