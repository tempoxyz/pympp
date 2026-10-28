---
pympp: minor
---

Added `mpp.x402.fastapi.payment_middleware` and the supporting `Negotiator` class, enabling MPP payments on routes already protected by the official x402 FastAPI middleware. Added a new `x402` optional dependency extra (`pip install "pympp[x402]"`) covering `fastapi`, `x402`, `eth-account`, and related packages.
