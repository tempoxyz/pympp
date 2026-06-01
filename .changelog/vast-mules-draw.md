---
pympp: patch
---

Added strict validation for payment method IDs, requiring them to match `1*LOWERALPHA` (lowercase letters only). Updated `Receipt` default method from empty string to `"tempo"` and fixed test fixtures to use valid method IDs.
