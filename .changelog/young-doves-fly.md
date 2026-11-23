---
pympp: patch
---

Fixed auth-param parsing to require comma separators between auth-params, following the grammar `auth-param *( OWS "," OWS auth-param )`. Whitespace-separated or otherwise malformed auth-params are now correctly rejected with a `ParseError`.
