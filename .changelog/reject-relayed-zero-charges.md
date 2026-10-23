---
pympp: patch
---

Reject zero-amount Tempo charge challenges from an HTTP host other than the challenge realm before signing a transaction. Servers using a different configured realm can be explicitly pinned with `trusted_tempo_realms` for their HTTP origin.
