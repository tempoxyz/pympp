---
pympp: minor
---

Added Zone payments to the Tempo charge method: clients pay by withdrawing from a Zone balance with the new `zone` option, and servers accept Zones with the `zones` option, with an opt-in `zone_credential_grace_ms` for zone credentials settled before their challenge expired. Added the `Zone` configuration class, `ZoneSettlementPendingError` and `ZoneWithdrawalBouncedError`.
