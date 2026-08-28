---
pympp: minor
---

Added MACH token metadata and `fee_tokens_for_chain` helper to the Tempo method, along with a `get_challenge_priority` hook that prefers charge challenges the configured payer can fund directly. Introduced async challenge selection (`select_challenge`) to `PaymentRuntime` and updated the MCP client to apply method-owned priorities when multiple compatible challenges are offered.
