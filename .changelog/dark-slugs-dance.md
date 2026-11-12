---
pympp: minor
---

Changed `CredentialReplayedError` to respond with HTTP 402, a fresh challenge and the `invalid-challenge` problem type (previously 403 and `verification-failed`), aligning with the core spec's status table for already-used challenges; replayed x402 payments still get a 403 without a new offer, and MCP sends the problem in the -32042 error's `data.problem`. Restricted payment method IDs to lowercase letters only (`1*LOWERALPHA`), breaking names containing digits, hyphens, colons, or underscores (e.g. `"stripe-pi"` must become `"stripepi"`). Changed the client to stop after a paid retry answered with `invalid-challenge` or with a 402 whose body cannot say why (such as a HEAD response), to avoid double payments. Added server-side validation of method names at startup and rejection of requests carrying multiple Payment credentials.
