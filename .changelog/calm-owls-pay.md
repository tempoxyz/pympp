---
pympp: minor
---

Added `Credential.payer`, which returns the payer address parsed from a `did:pkh:eip155:<chainId>:<address>` credential source, or `None` when the source is absent or malformed. Tempo pull-mode (transaction) credentials that carry a source are now rejected unless the source is on the charge chain and names the transaction sender (the keychain root account for access-key signatures), matching the existing push-mode binding.
