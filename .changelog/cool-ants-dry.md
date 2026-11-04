---
pympp: minor
---

Added an `http_client` parameter to the Tempo client `charge()` and `TempoMethod`. Every RPC call the payer makes goes through the given `httpx.AsyncClient`, so it can send a Tempo API key in the `tempo-api-key` header to the hosted RPC (`https://api.tempo.xyz/rpc`), as the server side already allowed.
