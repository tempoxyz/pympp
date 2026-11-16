---
pympp: major
---

Restricted the accepted credential header to `Payment-Authorization` only, rejecting any other non-default header with a `ValueError`/`ParseError` (previously any valid HTTP header name was accepted). Updated `advertised_credential_header`, `parse_www_authenticate`, `parse_authorization`, and the MCP client challenge parser to enforce this constraint, and introduced the `is_payment_authorization_header` helper for case-insensitive comparisons.
