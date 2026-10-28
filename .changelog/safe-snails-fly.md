---
pympp: patch
---

Fixed several bugs flagged by fuzzing, mutation, and adversarial tests: converted `RecursionError` from deeply nested JSON in `_b64_decode` to a proper `ParseError`; added correct lone-surrogate handling in body digest serialization to match JavaScript's `JSON.stringify`/`TextEncoder` behaviour; wrapped `rlp.DecodingError` in `decode_fee_payer_envelope` as `ValueError` and propagated it as `VerificationError` in `ChargeIntent`; rejected nonzero call values in sponsored swap patterns; and gave each `Mpp` event handler an isolated snapshot of the payload so one listener's mutations cannot affect subsequent handlers or the returned payment data.
