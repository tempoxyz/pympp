---
pympp: patch
---

Forward `meta` through direct `Mpp.charge()` and `Mpp.pay()` verification. HTTP framework scope now includes the request method and preserves configured `_mppx_scope` under `custom` alongside actual framework fields, preventing configured scope from disabling route binding.

Server-issued challenges include a random HMAC-bound `_mpp_nonce` in opaque metadata even when expiry is fixed. The metadata key is reserved; direct and composed verification preserve application metadata checks. Previously issued nonce-free challenges remain valid only when all other bindings match; low-level `Challenge.create()` remains deterministic. Outstanding HTTP credentials without method binding must obtain a fresh challenge after upgrading.

Challenge uniqueness does not authenticate the presenter of a stolen complete credential. Bind trusted authenticated account/session context in `meta` when identity matters, and enforce application authorization. A user-supplied payer address is not authentication. Use a shared atomic replay store across processes and replicas.

This release requires draining payment traffic before an atomic rollout, or version-sticky issuance and retries until outstanding challenges expire. `unique_challenges=False` disables only nonce issuance: it does not preserve old HTTP method scope, custom scope representation, or previously dropped direct metadata. Mixed versions can reject settled hash payments and cause duplicate payment. Nonce-only staging is safe only when every other binding already matches, and retains collision risk during that phase.

Lifecycle APIs normalize issuance metadata, legacy empty metadata remains accepted, and transient verification errors preserve the authenticated challenge for credential reuse. Invalid-payload errors still issue fresh challenges. Malformed opaque values are rejected by composed verification. Both mapping and scalar custom scopes are preserved in full under `custom`, preventing framework field names from silently discarding application bindings.
