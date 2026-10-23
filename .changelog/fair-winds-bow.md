---
pympp: patch
---

Fixed auth-param name parsing to be case-insensitive per RFC 9110 §11.2, normalizing parameter keys to lowercase before processing. Added tests to verify mixed-case and uppercase parameter names are handled correctly, and that duplicate detection works across different cases.
