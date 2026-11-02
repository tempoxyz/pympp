---
pympp: patch
---

Fixed a bug where automatic retries after submitting an x402 authorization could create multiple independently spendable payments for a single request. Stopped retrying after receiving a 402 response when an x402 authorization has already been sent.
