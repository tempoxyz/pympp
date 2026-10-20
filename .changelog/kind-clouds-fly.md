---
pympp: patch
---

Updated documentation and code comments to clarify external fee-payer service requirements and responsibilities. Added explicit guidance that external sponsors must independently authorize, validate, simulate, and enforce spending limits before releasing a broadcastable signature, since pympp cannot enforce an external sponsor's policy.
