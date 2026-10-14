---
pympp: minor
---

Added `Credential.payer` property that parses and returns the payer address from a `did:pkh:eip155:<chainId>:<address>` credential source, returning `None` when the source is absent or malformed. Extracted the `did:pkh` parser into a shared `mpp._did` module, consolidating the previously duplicated implementation in Tempo hash credential verification.
