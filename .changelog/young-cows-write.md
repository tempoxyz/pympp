---
pympp: patch
---

Fixed quoted-string auth-param parsing to follow RFC 9110 quoted-pair semantics: a backslash yields the next character, so `\uXXXX` reads as `uXXXX` instead of being decoded. Formatting now rejects characters above U+00FF in bound parameters (`realm`, `id`, `method`, `intent`, `digest`, `expires`, `header`), and `Mpp` raises `ValueError` at construction for such a realm (explicit or from the environment) or method intent. `description` still writes `\uXXXX` escapes, and the MCP transport keeps the configured description in its challenges. Clients now refuse a challenge whose bound parameter a pre-upgrade server escaped as `\uXXXX`, before creating a credential, and raise `LegacyUnicodeEscapedChallengeError` when no other challenge is payable.
