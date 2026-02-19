---
pympp: patch
---

Added call validation to the fee payer co-signing flow to prevent the server from sponsoring arbitrary transactions. The `_cosign_as_fee_payer` method now accepts an optional `request` parameter and validates that transaction calls target the expected currency contract with the correct recipient, amount, and memo before signing. Added comprehensive tests for the validation logic.
