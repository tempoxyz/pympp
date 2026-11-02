---
pympp: patch
---

Bound sponsored session top-ups with atomic rolling per-payer and aggregate fee allowances. Retain usage after successful and uncertain transactions so sequential top-ups cannot reset the sponsor's budget. Share the compare-and-set store and policy across instances using a sponsor.

Sponsored sessions now require a compare-and-set backend; incompatible stores fail when configured or attached. Sponsored top-ups must be signed by the channel payer and consume allowance only after preflight simulation, immediately before submission. Defaults allow five top-ups per channel payer and 100 across the sponsor in a rolling day; configure the policy for the deployment's traffic and acceptable spend. The aggregate fee budget is independent of per-transaction fee overrides.
