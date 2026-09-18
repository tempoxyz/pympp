---
pympp: patch
---

Fixed Stripe crypto PaymentIntent amounts to floor to whole cents instead of rounding, ensuring recorded amounts never exceed the settled on-chain amount. Fractional-cent payments below one cent continue to be skipped.
