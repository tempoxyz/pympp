---
pympp: patch
---

Rejected malformed Unicode in decoded payment headers before verification, returning ordinary parse failures instead of UTF-8 encoding exceptions. Added tests covering lone surrogates in credential fields, nested payloads, and valid supplementary Unicode.
