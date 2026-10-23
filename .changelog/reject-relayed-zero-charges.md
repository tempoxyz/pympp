---
pympp: patch
---

Reject zero-amount Tempo charge challenges from an HTTP host other than the challenge realm before signing a transaction. This can affect SDK servers whose default realm is an app name or `localhost`; clients can explicitly pin that realm to its HTTP origin with `trusted_tempo_realms`. MCP clients, which have no HTTP host, require an explicit trusted realm before signing a zero-amount Tempo charge.
