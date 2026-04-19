---
pympp: patch
---

Defaulted `chain_id` to 4217 (mainnet) in the `tempo()` function, removing the need to pass it explicitly. Removed the hardcoded testnet fee payer URL fallback, requiring explicit fee payer configuration on mainnet. Updated tests and docs accordingly.
