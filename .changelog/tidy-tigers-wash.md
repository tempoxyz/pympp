---
pympp: patch
---

Fixed base64url input validation to reject non-alphabet characters instead of silently discarding them, and tightened credential echo field parsing to require `realm`, `intent`, and `request` as non-optional strings matching mppx's `ChallengeEcho` schema.
