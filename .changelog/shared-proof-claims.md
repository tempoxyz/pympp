---
pympp: patch
---

Zero-amount charge proofs are now claimed under mppx's `mppx:charge:proof:<challenge id>` store key, which session bootstrap already uses, so a proof accepted by one can't be accepted again by the other and stores shared with mppx see the same claims.
