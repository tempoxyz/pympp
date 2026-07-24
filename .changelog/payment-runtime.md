---
pympp: minor
---

Added an owned-loop payment runtime shared by sync and async HTTP and explicit
MCP clients, with method factories, lifecycle contexts, origin policy, events,
bounded fail-closed uncertain-outcome protection, and scoped HTTPX
instrumentation with a tested HTTPX 0.27/0.28 compatibility matrix. Paid HTTP
retries also preserve cookies set by the challenge response.
