---
pympp: patch
---

Floor recorded Stripe crypto PaymentIntent amounts to whole cents so fractional-cent on-chain payments are not rounded up. Continue skipping amounts below one cent.
