---
pympp: patch
---

Fixed Tempo session voucher and close authorization verification to reject secp256k1 signatures with a high `s` value, which Tempo does not accept onchain, matching mppx.
