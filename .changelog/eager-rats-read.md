---
pympp: minor
---

Removed custom primary Tempo charge memos. The `memo` charge option and `MethodDetails.memo` field have been removed; clients now always generate attribution memos bound to the challenge and realm, and servers always verify that binding. Split-specific memos remain supported.
