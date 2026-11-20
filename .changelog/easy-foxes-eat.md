---
pympp: minor
---

Added `assert_credential_source_is_payer` as a new public verification function that binds a session-open credential's `source` to the payer authenticated by the signed transaction (direct, access-key, or inline-authorization signatures). Session opens now reject credentials whose `source` does not match the transaction payer, aligning with mppx behaviour. Also hardened WebAuthn signature parsing with an upper-bound size check and a more efficient split search.
