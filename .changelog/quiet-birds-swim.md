---
pympp: patch
---

Fixed Tempo attribution memos to be deterministically bound to challenge IDs using a keccak256-derived nonce instead of random bytes. Added `verify_challenge_binding` to enforce that verified payments carry a memo matching the specific challenge being redeemed.
