---
pympp: patch
---

Fixed fail-closed expiry enforcement in `ChargeIntent.verify`: requests with a missing `expires` challenge parameter are now rejected instead of silently allowed through.
