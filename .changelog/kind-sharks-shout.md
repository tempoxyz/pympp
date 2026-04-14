---
pympp: patch
---

Fixed `decode_fee_payer_envelope` to return a `SignedKeyAuthorization` object instead of raw RLP bytes when a key authorization is present in the fee payer envelope.
