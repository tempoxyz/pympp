---
pympp: minor
---

Added `PaymentMiddleware` ASGI middleware that gates any ASGI app behind a payment challenge, and added a `select_offers` hook to `Mpp` for narrowing which composed offers are advertised to clients. Exported new public types `ServerOffer`, `OfferSelectionContext`, and `SelectOffers` to support the hook.
