---
pympp: patch
---

Fixed quoted-string auth-param parsing to follow RFC 9110 quoted-pair semantics, where a backslash yields the next character literally rather than decoding `\uXXXX` sequences as Unicode. Added Latin-1 validation to `_escape_quoted` for bound header fields, and introduced a separate `_escape_quoted_text` helper for unbound display fields (such as `description`) that still emits `\uXXXX` escapes for non-Latin-1 characters.
