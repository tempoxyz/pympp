---
pympp: patch
---

Fixed a bug where shared challenge bindings were not properly released after failed or rejected sponsored charge attempts. Refactored the admission release logic to track individual attempt IDs within a shared binding, ensuring bindings are only deleted once all concurrent attempts have safely concluded.

When replicas share an admission store, drain old replicas before allowing upgraded replicas to accept sponsored charges. Older versions cannot read the new ownership fields and reject same-transaction retries against new bindings. Existing legacy bindings remain conservatively retained until expiry or definitive transaction reconciliation; do not clear admission records during the upgrade.
