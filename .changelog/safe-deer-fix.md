---
pympp: minor
---

Added `AutoSwap` dataclass and `auto_swap` parameter to `charge()` to automatically swap a missing charge currency through the Tempo stablecoin DEX. Added `PaymentMiddleware` ASGI middleware, `select_offers` hook on `Mpp`, and exported `ServerOffer`, `OfferSelectionContext`, and `SelectOffers` types; also fixed the `SWAP_EXACT_AMOUNT_OUT_SELECTOR` function selector.
