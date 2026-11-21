---
pympp: patch
---

Fixed quoted-string auth-param parsing to follow RFC 9110 quoted-pair semantics: a backslash yields the next character, so `\uXXXX` reads as `uXXXX` instead of being decoded. Formatting now rejects characters above U+00FF in bound parameters (`realm`, `id`, `method`, `intent`, `digest`, `expires`, `header`), and `Mpp` raises `ValueError` at construction for such a realm, explicit or from the environment. `description` still writes `\uXXXX` escapes, and the MCP transport keeps the configured description in its challenges.
