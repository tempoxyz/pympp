---
pympp: patch
---

Replaced bare `assert` statements with explicit `ValueError` exceptions in keychain signature validation and `VerifiableWrappedIntent`, providing clearer error messages for invalid `msg_hash` length, malformed `root_account` addresses, and unexpected intent types. Added corresponding tests to cover the new validation paths.
