---
pympp: minor
---

Added `Credential.payer`, which returns the payer address parsed from a `did:pkh:eip155:<chainId>:<address>` credential source, or `None` when the source is absent or malformed. The `did:pkh` parser is now shared between `Credential` and Tempo hash credential verification.
