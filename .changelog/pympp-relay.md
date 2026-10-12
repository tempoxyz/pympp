---
pympp: patch
---

Stopped requesting cached relay receipts during payment authorization. Reused credentials are rejected by relay replay protection; uncertain outcomes require separate recovery before executing protected operations.
