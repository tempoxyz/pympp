---
pympp: patch
---

Challenges whose `header` auth-param is anything other than `Payment-Authorization` (including an explicit `Authorization` or empty value) are now rejected and get no credential, while other challenges in the same 402 are still used. Constructing a challenge with a custom credential header name now raises `ValueError`.
