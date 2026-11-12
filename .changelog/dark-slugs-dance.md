---
pympp: major
---

Changed `CredentialReplayedError` to respond with HTTP 402 and the `invalid-challenge` problem type (previously 403 and `verification-failed`), aligning with the core spec's status table for already-used challenges. Restricted payment method IDs to lowercase letters only (`1*LOWERALPHA`), breaking names containing digits, hyphens, colons, or underscores (e.g. `"stripe-pi"` must become `"stripepi"`). Added client-side detection of `invalid-challenge` after a retry to avoid double payments, server-side validation of method names at startup, and rejection of requests carrying multiple Payment credentials.
