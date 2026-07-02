---
pympp: patch
---

Fixed MCP payment error detection to support the current MCP SDK's `McpError` shape, where error code and data are nested under an `error` attribute rather than directly on the exception. Added helper functions `_error_code` and `_error_data` to extract these fields from both error shapes.
