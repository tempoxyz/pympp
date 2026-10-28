---
pympp: patch
---

Enabled pyright strict mode across `src` and refactored internal type checks to use new `TypeGuard` helpers (`is_dict`, `is_mapping`, `is_list`). Added explicit `__all__` lists to public modules to codify existing exports.
