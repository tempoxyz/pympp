---
pympp: patch
---

Relay validation now reported the payload's settlement details instead of an empty `details` dict. Deeply nested keychain signatures no longer overflowed the stack in `_canonical_signature`.
