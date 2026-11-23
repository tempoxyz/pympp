---
pympp: minor
---

Added `sender_tags` parameter and attribute to `ZoneSettlementPendingError` to support Zones whose RPC redacts outbox events, returning multiple sender tag candidates instead of one. Added new public `sender_tag_candidates` async function, `SenderTagUnderivableError` exception, `MAX_SENDER_TAG_CANDIDATES` constant, and `wait_for_settled_withdrawal` function to derive and poll for settlements across multiple candidate sender tags.
