---
pympp: patch
---

Fixed currency validation during challenge matching by introducing a `_method_accepts_currency` helper that enforces case-insensitive currency comparison when a method has a configured currency constraint. Applied the check in both `PaymentRuntime` and `McpClient` challenge matching and credential creation paths.
