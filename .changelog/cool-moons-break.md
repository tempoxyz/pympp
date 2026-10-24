---
pympp: patch
---

Fixed preservation of challenge `description` field through credential serialization and deserialization. The `description` is now included when converting a `Challenge` to a `ChallengeEcho`, when formatting and parsing authorization headers, and when converting `MCPCredential` to core credentials.
