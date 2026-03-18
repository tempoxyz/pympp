---
pympp: patch
---

Added a pluggable `Store` interface and `MemoryStore` implementation for transaction hash replay protection in `ChargeIntent`. When a store is provided, verified tx hashes are recorded and subsequent attempts to reuse the same hash are rejected with a `VerificationError`.
