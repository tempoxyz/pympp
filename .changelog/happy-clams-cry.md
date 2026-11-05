---
pympp: patch
---

Fixed sponsored transaction simulation to include the fee payer signature in `eth_call` requests, as Tempo nodes (v1.18+) recover the fee payer only from `feePayerSignature` and otherwise bill the sender. The local fee payer now signs a simulation-only copy with a small gas buffer after the sender simulation passes, ensuring a reverting transaction is never signed for.
