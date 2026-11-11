---
pympp: major
---

Added `on_challenge` approval hook (`OnChallenge`/`ChallengeContext`) to `PaymentTransport` and `Mpp`, and added `check_secret_key`/`MIN_SECRET_KEY_BYTES` to enforce a 32-byte minimum secret. Changed `CredentialReplayedError` to respond with `402`/`invalid-challenge` instead of `403`/`verification-failed`, and tightened the payment method ID grammar to `1*LOWERALPHA` (breaking existing IDs containing digits, hyphens, colons, or underscores).
