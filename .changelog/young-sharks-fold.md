---
pympp: minor
---

Added `request_amount` function to allow payment methods to control their wire amount representation via an optional `parse_amount` hook. Methods that define `parse_amount(amount: str) -> str` now own their wire format, while methods without the hook continue to use the existing `parse_units` decimal-to-base-units conversion.
