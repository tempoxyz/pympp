---
pympp: patch
---

Tempo charge clients now reject primary and split recipients that are not 20-byte addresses, and transfer amounts outside uint256, before signing, so every transfer argument encodes as exactly one ABI word and the amount caps bound the signed amount.
