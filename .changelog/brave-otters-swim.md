---
pympp: minor
---

Added `mpp.methods.evm`, a payment method for standard EVM chains (e.g. Base) that settles charges with a plain ERC-20 `transfer` instead of Tempo's native transaction type. Install with `pip install "pympp[evm]"`.
