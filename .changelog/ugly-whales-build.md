---
pympp: minor
---

Added `extensions` field to `Receipt` to capture and preserve method-specific top-level fields (e.g. Tempo-specific fields like `challengeId`, `originTxHash`) during parsing and round-tripping of Payment-Receipt headers.
