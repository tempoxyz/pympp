---
pympp: patch
---

Signed all Tempo charge transactions with expiring nonces, matching the TypeScript SDK. Unsponsored charges previously used the sequential nonce from `eth_getTransactionCount(..., "pending")`, which raced under concurrent payments from one key and ignored a non-zero challenge `nonce_key`. `valid_before` is now capped at the whole second after the challenge expiry, so the transaction stays valid for as long as the challenge does. `FEE_PAYER_VALID_BEFORE_SECS` is deprecated in favor of `EXPIRING_NONCE_VALID_BEFORE_SECS`. The client now signs each charge challenge at most once per signer, reusing the credential for repeated or concurrent requests until its transaction's `valid_before` passes.
