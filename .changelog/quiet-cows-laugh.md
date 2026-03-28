---
pympp: minor
---

Added Stripe payment method (`mpp.methods.stripe`) supporting the Shared Payment Token (SPT) flow for HTTP 402 authentication. Includes client-side `StripeMethod` and `stripe()` factory, server-side `ChargeIntent` for PaymentIntent verification via Stripe SDK or raw HTTP, Pydantic schemas, and a `stripe` optional dependency group.
