---
pympp: minor
---

Added 0x78 fee payer envelope encoding/decoding module with `encode_fee_payer_envelope` and `decode_fee_payer_envelope` functions. Updated `ChargeIntent._cosign_as_fee_payer` to use the new 0x78 wire format instead of 0x76, including sender address verification against the recovered signer. Exported `USDC`, `PATH_USD`, and `default_currency_for_chain` from the tempo package public API.
