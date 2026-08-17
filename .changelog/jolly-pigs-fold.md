---
pympp: patch
---

Reverted early termination on repeated actionable challenges, allowing the payment transport to retry payment even when the same challenge ID is received multiple times.
