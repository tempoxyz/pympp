---
pympp: patch
---

Fixed `parse_units` returning silently wrong amounts. Scaling ran through the active decimal context, so a value with more than 28 significant digits was rounded to a different integral value and returned without error; it is now scaled with exact integer arithmetic. A negative `decimals` is also rejected instead of dividing the amount — `("100", -2)` previously returned `1` — and `transform_units` no longer accepts a boolean `decimals`, which `bool` being an `int` subclass would have applied as a scale of 1.
