---
pympp: patch
---

Wrapped `rlp.encode` results in `bytes()` calls in test assertions to fix Pyright type compatibility.
