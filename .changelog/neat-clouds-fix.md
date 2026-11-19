---
pympp: minor
---

Added `pay_to_resolver` (and `facilitator_pay_to_resolver`) functions that return a caching resolver for a facilitator's `payTo` address, refreshing it every `ttl` seconds. Made `charge()`'s `recipient` parameter optional — when omitted, the recipient is automatically read from the facilitator's `payTo` and cached for 5 minutes, with graceful handling of address rotation and refresh failures.
