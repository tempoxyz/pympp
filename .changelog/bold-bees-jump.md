---
pympp: minor
---

Aligned servers and clients with the core spec: rejected credentials report specific problem types, replays get `402` with a fresh `invalid-challenge`, HMAC secrets must be at least 32 bytes, and method IDs must be lowercase letters. Added the client `on_challenge` approval hook. Tempo pull transactions no longer need the attribution memo and accept other realms' attribution memos, while Tempo push (hash) credentials still require the memo bound to their challenge. Servers reject invalid method IDs at startup, and clients, including the MCP client, never pay again automatically after a paid retry is answered with a new Challenge.
