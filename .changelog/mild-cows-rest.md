---
pympp: patch
---

Rejected challenges whose `header` auth-param is anything other than `Payment-Authorization` (including an explicit `Authorization` or empty value), so they get no credential while other challenges in the same 402 are still used. Made constructing a challenge with a custom credential header name raise `ValueError` instead of advertising it.
