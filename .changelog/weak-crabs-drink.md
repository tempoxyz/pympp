---
pympp: major
---

Restricted payment method IDs to lowercase letters only (`a-z`), rejecting names that previously matched the broader grammar (digits, hyphens, underscores, colons). `Mpp` now raises `ValueError` at startup for any registered method whose name contains non-lowercase characters, `Challenge` and `Receipt` parsing and formatting raise `ParseError` for invalid IDs, and `verify_or_challenge` validates the method name before any payment settles. New public helpers `is_valid_payment_method_id`, `validate_payment_method_id`, and `receipt_with_valid_method` were added to `mpp._parsing`.
