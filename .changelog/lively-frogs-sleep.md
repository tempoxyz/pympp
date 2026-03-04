---
pympp: patch
---

Applied `transform_request` method hook in `Mpp.charge` and `Mpp.pay` helpers, ensuring the method's request transform is called before verification. Added tests covering both helpers.
