---
pympp: patch
---

Fixed `transferWithMemo` acceptance in pre-broadcast validation when no explicit memo is required, and propagated `rpc_url` from `tempo()` to intents automatically so `ChargeIntent` no longer requires it to be passed directly.
