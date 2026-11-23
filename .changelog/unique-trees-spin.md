---
pympp: patch
---

Fixed paying from a Zone whose RPC leaves outbox events out of receipts: the Tempo charge client now derives the withdrawal's sender tag from the Zone's outbox. `ZoneSettlementPendingError` gained `sender_tags`, which lists every candidate tag when the exact one isn't known.
