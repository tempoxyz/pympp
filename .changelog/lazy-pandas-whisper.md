---
pympp: minor
---

Added `x402_extra` parameter to `ChargeIntent` and `charge()` for passing custom fields into x402 payment requirements' `extra` object. Added `facilitator_pay_to()` helper and `pay_to()` function to retrieve a facilitator's `payTo` address via `GET /supported`, along with the `SupportsSupported` protocol, `SupportedKind`/`SupportedResponse` types, and `supported()` method on `HttpFacilitator`.
