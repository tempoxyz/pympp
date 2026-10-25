---
pympp: patch
---

Fixed payment method ID parsing to accept the extended charset used by mppx, allowing digits, colons, underscores, and hyphens after a leading lowercase letter (e.g. `tempo-v2`, `vendor:method`, `x402`). Updated tests to reflect the new valid and invalid method ID sets.
