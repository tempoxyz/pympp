---
pympp: minor
---

Added `on_challenge` approval hook to `Mpp` and `PaymentTransport`, allowing callers to inspect, approve, decline, or replace a payment before it is sent. Introduced the `ChallengeContext` dataclass and `OnChallenge` type alias as new public API surface.
