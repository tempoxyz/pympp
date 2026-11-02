---
pympp: patch
---

Fixed sponsored session top-ups to enforce atomic rolling per-payer and aggregate fee allowances over a 24-hour window. Usage is retained after successful, failed, and uncertain transactions so sequential top-ups cannot reset the sponsor's budget. Added `SessionSponsorshipLimit` to configure and share limits across instances using a shared compare-and-set store.
