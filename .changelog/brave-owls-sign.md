---
pympp: patch
---

Signed all Tempo charge transactions with expiring nonces, matching the TypeScript SDK. Unsponsored charges previously used the sequential nonce from `eth_getTransactionCount(..., "pending")`, which raced under concurrent payments from one key and ignored a non-zero challenge `nonce_key`. `valid_before` is now capped at the challenge expiry, and `FEE_PAYER_VALID_BEFORE_SECS` is renamed to `EXPIRING_NONCE_VALID_BEFORE_SECS`.
