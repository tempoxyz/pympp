---
pympp: patch
---

Fixed a potential stack overflow in `_canonical_signature` by converting the recursive keychain nesting traversal to an iterative loop. Fixed relay validation to report settlement details extracted from the credential payload instead of returning an empty `details` dict.
