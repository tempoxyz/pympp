---
pympp: patch
---

Preserve `externalId`, `subscriptionId`, `extra`, and extension fields when converting and parsing MCP payment receipts. Preserve the payment method when converting an MCP receipt to a core receipt. Extension fields cannot override standard MCP receipt fields.
