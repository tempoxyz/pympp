---
pympp: patch
---

Added chain ID verification to Tempo charge settlement. The RPC endpoint's reported chain is now validated against the charge request's advertised chain ID for hash credentials, and serialized transaction payloads are checked to ensure their embedded chain ID matches the charge before processing.
