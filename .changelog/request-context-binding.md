---
pympp: patch
---

Forward `meta` through direct `Mpp.charge()` and `Mpp.pay()` verification. HTTP framework scope now includes the request method and merges actual framework fields with configured `_mppx_scope`, preventing configured scope from disabling route binding.

Server-issued challenges include a random HMAC-bound `_mpp_nonce` in opaque metadata even when expiry is fixed. The metadata key is reserved; direct and composed verification preserve application metadata checks. Previously issued challenges remain valid until expiry; low-level `Challenge.create()` remains deterministic. Outstanding HTTP credentials without method binding must obtain a fresh challenge after upgrading.

Challenge uniqueness does not authenticate the presenter of a stolen complete credential. Bind trusted authenticated account/session context in `meta` when identity matters, and enforce application authorization. A user-supplied payer address is not authentication. Use a shared atomic replay store across processes and replicas.
