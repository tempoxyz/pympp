---
pympp: patch
---

Added Python 3.11 support by lowering the `requires-python` constraint from `>=3.12` to `>=3.11`, updating tooling targets accordingly, and replacing PEP 695 generic syntax with `TypeVar` for compatibility.
