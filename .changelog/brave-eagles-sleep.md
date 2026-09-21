---
pympp: patch
---

Fixed Unicode handling in challenge auth-params by encoding non-Latin-1 characters as UTF-16 escapes during serialization and decoding those escapes (including surrogate pairs) during parsing.
