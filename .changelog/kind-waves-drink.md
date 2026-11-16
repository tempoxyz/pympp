---
pympp: minor
---

Added an expiry grace marker system (`EXPIRY_GRACE_KEY`) that embeds an HMAC-bound flag in challenge opaque metadata, ensuring only challenges issued while a grace is configured can redeem credentials after expiry. Fixed Zone withdrawal logic to retain late-redeemed credentials for retries of their own challenge and raise `ZoneSettlementPendingError` for other challenges until the redemption window closes; also fixed opaque metadata comparison to strip reserved keys and restricted `zone_credential_grace_ms` from being used together with `relay`.
