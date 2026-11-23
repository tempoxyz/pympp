---
pympp: patch
---

Fixed Tempo session voucher and close authorization verification to reject secp256k1 signatures with a high `s` value, which Tempo does not accept onchain, matching the behavior of mppx. Voucher signing now normalizes a signer's high-`s` signature to its low-`s` equivalent.
