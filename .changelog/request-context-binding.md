---
pympp: patch
---

Forward `meta` through direct `Mpp.charge()` and `Mpp.pay()` verification. HTTP framework scope now includes the request method and merges actual framework fields with configured `_mppx_scope`, preventing configured scope from disabling route binding.

Server-issued challenges include a random HMAC-bound `_mpp_nonce` in opaque metadata even when expiry is fixed. The metadata key is reserved; direct and composed verification preserve application metadata checks. Previously issued challenges remain valid until expiry; low-level `Challenge.create()` remains deterministic. Outstanding HTTP credentials without method binding must obtain a fresh challenge after upgrading.

Challenge uniqueness does not authenticate the presenter of a stolen complete credential. Bind trusted authenticated account/session context in `meta` when identity matters, and enforce application authorization. A user-supplied payer address is not authentication. Use a shared atomic replay store across processes and replicas.

For rolling upgrades, first deploy nonce-aware verification with `unique_challenges=False` on `Mpp.create`, `pay`, or `verify_or_challenge`; enable the default after every replica is upgraded. This phase retains collision risk. Old verifiers reject new nonced challenges, potentially after a hash payment has settled. Atomic rollout or version-sticky retries are alternatives. Lifecycle APIs normalize issuance metadata, legacy empty metadata remains accepted, and transient verification errors preserve the authenticated challenge for credential reuse. Invalid-payload errors still issue fresh challenges. Malformed opaque values are rejected by composed verification, and scalar custom scopes are preserved under `custom` alongside actual framework scope.
