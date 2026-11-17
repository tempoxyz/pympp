---
pympp: patch
---

Fixed payment method ID validation to restrict to lowercase letters only (`1*LOWERALPHA`), aligning with the spec grammar instead of the previously over-permissive regex that also accepted digits, hyphens, underscores, and colons. Added validation to `format_www_authenticate` so invalid method IDs are caught on output as well as input.
