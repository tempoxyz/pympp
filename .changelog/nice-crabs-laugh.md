---
pympp: patch
---

Fixed cancelled paid MCP retries to report unknown payment outcomes on both asyncio and Trio, preventing callers from blindly retrying a payment that may have settled.
