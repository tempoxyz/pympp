---
pympp: patch
---

Fixed `parse_units` silently returning a rounded amount for values with more than 28 significant digits. Scaling ran through the active decimal context, so a long amount was rounded to a different integral value and returned without error; it is now scaled with exact integer arithmetic.
