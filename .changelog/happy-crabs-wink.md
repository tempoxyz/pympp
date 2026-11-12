---
pympp: minor
---

Added identity verification primitives (`mpp.identity`) and the Tempo ID provider (`mpp.extensions.identity.tempo`, installable via `pympp[tempo-id]`), enabling routes to require verified identity in addition to payment. Extended `PaymentTransport` and `Mpp` with an optional `identity` parameter for client-side provers, and added `identity` and `rejection` fields to `PaymentVerified` and `PaymentRequired` respectively.
