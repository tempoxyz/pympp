---
pympp: minor
---

Added support for Zone RPCs that redact outbox events by deriving sender tag candidates from the outbox's `lastFallbackNonce`. Introduced `sender_tag_candidates()` and `wait_for_settled_withdrawal()` functions, expanded `ZoneSettlementPendingError` with a new optional `sender_tags` parameter and attribute, and updated the Tempo client to handle multiple candidate sender tags when a Zone RPC hides the `WithdrawalRequested` event.
