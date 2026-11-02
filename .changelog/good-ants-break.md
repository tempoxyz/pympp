---
pympp: patch
---

Fixed sponsored charge admission to atomically bind each challenge to a single transaction and serialize pending charges per payer and currency before simulation. Unknown outcomes now preserve both claims until reconciliation or expiry, preflight rejections release claims without consuming sponsorship, and configured stores must support `compare_and_set` or fail closed.
