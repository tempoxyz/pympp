---
pympp: minor
---

Added the `mpp.methods.tempo.session.client` module with `SessionManager`, `SessionMethod`, `session`, `session_manager`, and supporting types (`ChannelEntry`, `ChannelStore`, `JsonChannelStore`, `MemoryChannelStore`, `PaymentResponse`, etc.) for paying metered APIs through a single TIP-1034 payment channel. Extended `ChallengeContext` with optional `request` and `fetch` fields, and updated `PaymentRuntime.create_credential` to accept matching optional parameters. Added a `session-metered-api` Docker Compose example demonstrating 500 sub-cent calls, automatic top-ups, and a cooperative close.
