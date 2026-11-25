---
pympp: patch
---

Fixed unquoted auth-param value parsing to strictly enforce RFC 9110 token rules (`1*tchar`), rejecting non-token characters (e.g. backslashes, slashes) and empty token values with a `ParseError`. Added tests covering adjacent auth schemes and the stricter token validation.
