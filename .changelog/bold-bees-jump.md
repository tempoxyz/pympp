---
pympp: minor
---

Aligned servers and clients with the core spec: rejected credentials report specific problem types, replays get `402` with a fresh `invalid-challenge`, HMAC secrets must be at least 32 bytes, and method IDs must be lowercase letters. Added the client `on_challenge` approval hook and made the Tempo attribution memo optional.
