---
pympp: patch
---

Fixed base64url decoding of credentials, receipts and the challenge `request` and `opaque` parameters to reject characters outside the base64url alphabet instead of discarding them; a challenge whose `opaque` is not base64url now fails to parse. Credentials now require the challenge echo's `id`, `realm`, `method`, `intent` and `request` to be strings, as mppx's `ChallengeEcho` schema does.
