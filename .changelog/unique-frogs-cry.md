---
pympp: patch
---

Fixed a bug where shared challenge bindings were not properly released after failed or rejected sponsored charge attempts. Refactored the admission release logic to track individual attempt IDs within a shared binding, ensuring bindings are only deleted once all concurrent attempts have safely concluded.
