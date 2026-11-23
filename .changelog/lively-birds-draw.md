---
pympp: patch
---

Fixed Tempo session voucher and close authorization verification to reject secp256k1 signatures with a high `s` value, which Tempo does not accept onchain, matching the behavior of mppx. Updated test vectors to reflect that high-`s` payer signatures are no longer considered valid.
