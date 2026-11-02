---
pympp: minor
---

Added new session features including `SessionSnapshot` type with serialization helpers, `SponsorshipLimit`, `ResolveSessionChannelId`, and `PreflightContext`/`PreflightFn` types. Extended `session()`, `session_manager()`, `SessionManager`, and `SessionMethod` with new optional parameters (`auto_swap`, `bootstrap`, `trusted_tempo_realms`, `voucher_state_max_age`, `charge_on_acceptance`, `sponsorship_limit`, `resolve_channel_id`), and added `preflight` field to `ServerMethod`.
