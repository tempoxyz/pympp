---
pympp: minor
---

Added support for additional payment receipt metadata fields (`external_id`, `subscription_id`, `funding_currency`, `extra`, and `extensions`) to `MCPReceipt`, with full round-trip serialization and propagation to/from the core `Receipt` type. Extensions are safely filtered to prevent overriding reserved receipt fields during serialization.
