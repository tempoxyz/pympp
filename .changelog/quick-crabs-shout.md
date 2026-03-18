---
pympp: patch
---

Raised `DEFAULT_GAS_LIMIT` from 100,000 to 1,000,000 for Tempo AA (type-0x76) transactions to account for their higher intrinsic gas cost (~270k for a single TIP-20 transfer).
