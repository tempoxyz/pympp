---
pympp: minor
---

Added fee payer policy enforcement for sponsored Tempo transactions, validating gas limits, fee caps, total fee budgets, validity windows, and access lists against per-chain policy defaults. Added call pattern validation to restrict sponsored transactions to approved selectors (transfers, and optionally an approve+swap prefix via the stablecoin DEX).
