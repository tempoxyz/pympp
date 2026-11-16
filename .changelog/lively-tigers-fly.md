---
pympp: minor
---

Added x402 Sign-In with X (SIWX) support, allowing wallets that prove their address to access resources without payment. Introduced the new `mpp.x402.siwx` module with `SiwxOptions`, `SiwxTransport`, `VerifiedProof`, and related types/functions, and added an optional `siwx` parameter to `mpp.methods.evm.server.charge` and `ChargeIntent`.
