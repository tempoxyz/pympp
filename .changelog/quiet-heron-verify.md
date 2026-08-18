---
pympp: patch
---

Fixed `verify_or_challenge` raising `TypeError` when a challenge carried a timezone-naive `expires`. Such a value parsed but could not be compared to an aware `now`, so an expired credential surfaced as a server error instead of a fail-closed rejection; it is now rejected like any other unusable `expires`.
