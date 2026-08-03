---
pympp: minor
---

Improved HTTP challenge parsing to correctly split merged `WWW-Authenticate` headers with quoted commas, added pass-through support for streaming request bodies on ordinary and unrelated 402 responses, and introduced `PaymentOutcomeUnknownError` (consolidated from the MCP client into core) to surface explicit errors when a paid retry outcome is uncertain due to network failures or task cancellation.
