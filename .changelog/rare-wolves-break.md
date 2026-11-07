---
pympp: minor
---

Added Zone payment support to the Tempo charge method, allowing clients to pay charges by withdrawing from a Zone balance when a challenge accepts that Zone. Added `Zone` configuration class, `ZoneSettlementPendingError`, `ZoneWithdrawalBouncedError` (raised when a Zone withdrawal bounces back to the payer's Zone balance; paying again withdraws again), `ZoneCredentialPayload` schema, and new `zone` / `zones` optional parameters to the client and server `charge()` functions.
