---
pympp: patch
---

Local fee sponsorship verifies secp256k1, P256 and WebAuthn root signatures before co-signing. Keychain senders are refused locally because root-account simulation does not enforce access-key authorization or spending limits; use an independently authorizing hosted sponsor for access keys. Multisig and forged envelopes remain refused.

Local charge sponsorship requires route-level `fee_payer=True`; configuring a local account alone leaves routes unsponsored so access-key clients retain a payable path. Hosted sponsorship still defaults on.
