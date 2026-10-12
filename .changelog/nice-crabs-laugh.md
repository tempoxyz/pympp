---
pympp: patch
---

Fixed MCP client to correctly catch `asyncio.CancelledError` during paid tool retries and report them as unknown payment outcomes, preventing silent cancellation without proper error handling. Added a corresponding test to verify the behaviour.
