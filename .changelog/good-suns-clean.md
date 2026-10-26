---
pympp: patch
---

Fixed several correctness issues in the server engine: percent-encoded URL paths are now preserved distinctly in signed scopes and resource fields, credential settlement correctly validates group membership to prevent cross-store replay attacks, and custom scope matching is enforced during credential verification. Also fixed header encoding for non-ASCII bytes and added validation that intent callbacks return proper `Validation` results.
