---
pympp: patch
---

Fixed Stripe credential `externalId` binding so that the request-bound `externalId` is echoed in the credential payload (falling back to the configured value when absent). Added server-side validation that rejects credentials whose `externalId` does not match the route request's `externalId`, raising `InvalidChallengeError` before any Stripe API calls are made.
