---
pympp: minor
---

Added `on_challenge` approval hook to `Mpp` and `PaymentTransport`, allowing callers to inspect, approve, decline, or replace a payment before it is sent. Introduced the `ChallengeContext` dataclass and `OnChallenge` type alias as new public API surface. Added the `AttemptOutcome.sent` field, `False` for a rejected credential that never reached the server (declined, replaced or abandoned before sending), so a method can release what it reserved for it. Tempo sessions now roll back an automatic voucher increment when the hook declines or replaces the voucher.
