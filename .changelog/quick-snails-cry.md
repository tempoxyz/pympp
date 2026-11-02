---
pympp: minor
---

Added support for zero-amount proof credentials in Tempo charge verification, mirroring mppx behavior. Introduced `ProofCredentialPayload` (EIP-712 proof signatures), extended `CredentialPayload` and `ChargePayload` to include it, and added `MethodDetails.supportedModes` to restrict accepted settlement modes per challenge.
