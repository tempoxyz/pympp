---
pympp: patch
---

Persist server close transaction expiry separately from payer close requests so cancellation cannot reopen spending while an earlier close can still settle.
