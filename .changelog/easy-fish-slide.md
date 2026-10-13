---
pympp: patch
---

Fixed sponsored swap amount validation to constrain swap output tokens, amounts, and approvals during cosigning. Added checks ensuring the swap output token matches the payment currency, the output amount is positive and does not exceed the payment amount, and the approval amount matches the positive maximum swap input.
