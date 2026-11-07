---
pympp: minor
---

Added Zone payment support to the Tempo charge method, allowing clients to pay charges by withdrawing from a Zone balance when a challenge accepts that Zone. Added `Zone` configuration class, `ZoneSettlementPendingError`, `ZoneCredentialPayload` schema, and new `zone` / `zones` optional parameters to the client and server `charge()` functions.
