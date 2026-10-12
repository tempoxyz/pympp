---
pympp: patch
---

Rejected malformed Unicode in decoded payment headers before verification, returning ordinary parse failures instead of UTF-8 encoding exceptions.
