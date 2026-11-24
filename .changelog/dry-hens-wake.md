---
pympp: minor
---

Added two new public error classes, `InsufficientBalanceError` and `SpendingLimitExceededError`, to `mpp.errors` and the top-level `mpp` namespace. The Tempo charge client and session open/top-up transactions now raise these typed errors before signing when the pre-signing gas estimate simulation reverts due to an insufficient token balance or exceeded access key spending limit, rather than silently falling back to the default gas limit.
