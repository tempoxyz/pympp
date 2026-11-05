---
pympp: patch
---

Fixed sponsored transaction simulation to include the fee payer signature in `eth_call` requests, as Tempo nodes (v1.18+) recover the fee payer only from `feePayerSignature` and otherwise bill the sender. The sender simulation now runs at the transaction's exact gas limit, without fees, so a gas limit too low for the mined transaction is refused. The local fee payer then signs a simulation-only copy with a small gas buffer, clamped to its sponsor policy, after the sender simulation passes, ensuring a reverting transaction is never signed for. A sponsored simulation without the full gas buffer (a hosted fee payer's, whose signature binds the client's gas, or a local one clamped by the sponsor policy) passes when it fails only by running out of gas.
