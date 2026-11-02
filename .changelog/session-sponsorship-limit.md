---
pympp: patch
---

Bound sponsored session top-ups with atomic rolling per-payer and aggregate fee allowances. Retain usage after successful and uncertain transactions so sequential top-ups cannot reset the sponsor's budget. Share the compare-and-set store and policy across instances using a sponsor.
