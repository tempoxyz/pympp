---
pympp: patch
---

Fixed `verify_or_challenge` raising `TypeError` when a challenge carried a timezone-naive `expires` value. A naive timestamp parsed successfully but could not be compared to an aware `now`, surfacing as a server error instead of a fail-closed rejection; it is now rejected like any other invalid `expires`.
