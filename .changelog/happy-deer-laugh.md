---
pympp: patch
---

Rejected zero-amount Tempo charge challenges from HTTP hosts that don't match the challenge realm to prevent relay attacks. Added `trusted_tempo_realms` parameter to `PaymentTransport` and `Client` to explicitly pin origins to non-hostname realms.
