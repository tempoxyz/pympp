---
pympp: patch
---

Fixed Tempo charge transactions to always sign with expiring nonces (nonce_key=U256::MAX, nonce=0) for both sponsored and unsponsored charges, replacing the sequential `eth_getTransactionCount` nonce that caused race conditions under concurrent payments from one key and ignored non-zero challenge `nonce_key` values. Renamed `FEE_PAYER_VALID_BEFORE_SECS` to `EXPIRING_NONCE_VALID_BEFORE_SECS` and capped `valid_before` at the challenge expiry when provided.
