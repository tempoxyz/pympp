---
pympp: patch
---

Fixed paying from a Zone whose RPC redacts outbox events from receipts. Added `sender_tags` to `ZoneSettlementPendingError`, listing every sender tag a pending withdrawal may carry.
