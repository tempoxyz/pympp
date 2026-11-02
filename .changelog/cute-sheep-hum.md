---
pympp: patch
---

Fixed parsing of `WWW-Authenticate` challenge headers to reject malformed auth-params (sequential consumption matching mppx behaviour), invalid `digest` formats (must start with `sha-256=`), and invalid `expires` values (must be RFC 3339 date-time with timezone).
