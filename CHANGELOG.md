# Changelog

## 0.18.0 (2026-10-29)

### Minor Changes

- Aligned Tempo sponsorship, the Tempo client and x402 facilitators with mppx. Sponsored Tempo charges now check the transaction with two `eth_call` simulations, first from the sender and then as the final sponsored transaction, instead of `tempo_simulateV1`, which public Tempo RPCs refuse. A route asking for `fee_payer` on a server with no sponsor no longer advertises sponsorship; sponsorship stays opt-in per route. EVM offers ignore `fee_payer` and accept `external_id`, so one route can compose sponsored Tempo offers with EVM/x402 offers. A Tempo client built with `charge()` without `chain_id` or `rpc_url` pays on the chain the challenge names (mainnet or Moderato) instead of skipping it; pinned clients and directly built `TempoMethod`s keep their chain, and `allowed_chain_ids` is checked against the chain actually signed on. `HttpFacilitator` takes `create_auth_headers` for per-endpoint headers, and `mpp.x402.cdp.facilitator()` (the new `cdp` extra) authenticates to Coinbase's facilitator with a CDP API key, as `@coinbase/x402` does. (by @brendanjryan, [#365](https://github.com/tempoxyz/pympp/pull/365))

## 0.17.0 (2026-10-28)

### Minor Changes

- Added a `select_offers` hook to `Mpp` for narrowing which composed offers are advertised to clients, with the new public types `ServerOffer`, `OfferSelectionContext`, and `SelectOffers`. (by @brendanjryan, [#346](https://github.com/tempoxyz/pympp/pull/346))
- Added `mpp.x402.fastapi.payment_middleware` and the supporting `Negotiator` class, enabling MPP payments on routes already protected by the official x402 FastAPI middleware. Added a new `x402` optional dependency extra (`pip install "pympp[x402]"`) covering `fastapi`, `x402`, `eth-account`, and related packages. (by @brendanjryan, [#353](https://github.com/tempoxyz/pympp/pull/353))
- Added `SponsorBudget` to cap a local fee payer's aggregate in-flight sponsored fees across processes, with a new `sponsor_budget` parameter on `ChargeIntent` and `server.charge`. Added `CompareAndSetStore` protocol and implemented atomic `compare_and_set` on `MemoryStore`, `RedisStore` (requires `EVAL`), and `SQLiteStore` to support shared budget state. A store without usable `compare_and_set`, such as Redis denying `EVAL`, falls back to a process-scoped budget with a warning. (by @brendanjryan, [#354](https://github.com/tempoxyz/pympp/pull/354))
- Added `auto_swap` to the Tempo `charge()` client (`True` or an `AutoSwap` with currencies and slippage): when the payer lacks the charge currency, it buys the shortfall through the Tempo stablecoin DEX in the same transaction, or raises `InsufficientFundsError` when no fallback currency can fund it. (by @brendanjryan, [#347](https://github.com/tempoxyz/pympp/pull/347))
- Added x402 v2 client support to `mpp.x402`, exposing `X402Challenge`, `x402_challenges`, `is_x402_challenge`, and `payment_response` as new public API. Added a complete `examples/x402-client/` example demonstrating a pympp client paying a Coinbase x402 server on a local Anvil chain. (by @brendanjryan, [#362](https://github.com/tempoxyz/pympp/pull/362))
- Added a Base USDC rail to Stripe machine payments: `deposit_addresses['base']` enables `payments.base.charge()` and `default_methods(base=...)`, recording Base charges in Stripe. (by @brendanjryan, [#350](https://github.com/tempoxyz/pympp/pull/350))
- Added `PaymentMiddleware` ASGI middleware to `mpp.server.asgi` that gates HTTP requests behind a payment handler, returning a `402` challenge to unpaid clients and injecting `Payment-Receipt` headers into successful responses. Supports any ASGI-compatible framework and handles body binding, body replay, and non-HTTP scope pass-through. (by @brendanjryan, [#345](https://github.com/tempoxyz/pympp/pull/345))
- Added the OpenAPI payment discovery module (`mpp.discovery`) with `generate`, `generate_proxy`, and `validate` functions and supporting route and issue types. (by @brendanjryan, [#349](https://github.com/tempoxyz/pympp/pull/349))

### Patch Changes

- Tempo charge clients now reject primary and split recipients that are not 20-byte addresses, and transfer amounts outside uint256, before signing, so every transfer argument encodes as exactly one ABI word and the amount caps bound the signed amount. (by @brendanjryan, [#360](https://github.com/tempoxyz/pympp/pull/360))
- Added nightly mutation testing (mutmut) and coverage-guided fuzzing (atheris) infrastructure for protocol-critical modules. Includes GitHub Actions workflows, Makefile targets, fuzz harnesses for header parsers and transaction decoders, and a Hypothesis profile for deterministic mutation test runs. (by @brendanjryan, [#359](https://github.com/tempoxyz/pympp/pull/359))
- Added property-based tests for the server engine, challenge binding, and unit conversion, along with concurrency stress tests covering exactly-once settlement, replay-store claims, and client transport credential isolation. Registered a new `stress` pytest marker for heavy concurrency runs gated behind `MPP_STRESS=1`. (by @brendanjryan, [#357](https://github.com/tempoxyz/pympp/pull/357))
- Added a public API snapshot (`api/public-api.txt`) with a CI check to detect unintended API changes, and improved the CI coverage pipeline by adding branch coverage ratcheting, diff-cover checks for changed lines, and Redis service containers for all test matrix runs. (by @brendanjryan, [#356](https://github.com/tempoxyz/pympp/pull/356))
- Added property-based, store-contract, and engine-event test suites mirroring the mppx TypeScript test suite. No public API changes were made. (by @brendanjryan, [#355](https://github.com/tempoxyz/pympp/pull/355))
- Fixed several correctness issues in the server engine. Out-of-band `validate_credential` and `broadcast_credential` no longer guess between separately configured methods that share the credential's name and intent (they may settle through different replay stores): pass `request=` and it must match exactly one of them, or the credential is refused; copies from one configuration, such as one per accepted currency, still settle without it. Custom scope matching is now enforced during credential verification, percent-encoded URL paths stay distinct in signed scopes and resource fields, header encoding handles non-ASCII bytes, and intent callbacks must return `Validation` results. (by @brendanjryan, [#343](https://github.com/tempoxyz/pympp/pull/343))
- Added Stripe Connect settlement (`connect`) to Stripe SPT charges and to Tempo payments recorded through `MachinePayments`. The settlement stays server-side, out of the challenge, and is validated before the payment settles. (by @brendanjryan, [#348](https://github.com/tempoxyz/pympp/pull/348))
- Fixed several bugs flagged by fuzzing, mutation, and adversarial tests: converted `RecursionError` from deeply nested JSON in `_b64_decode` to a proper `ParseError`; added correct lone-surrogate handling in body digest serialization to match JavaScript's `JSON.stringify`/`TextEncoder` behaviour; wrapped `rlp.DecodingError` in `decode_fee_payer_envelope` as `ValueError` and propagated it as `VerificationError` in `ChargeIntent`; rejected nonzero call values in sponsored swap patterns; and gave each `Mpp` event handler an isolated snapshot of the payload so one listener's mutations cannot affect subsequent handlers or the returned payment data. (by @brendanjryan, [#361](https://github.com/tempoxyz/pympp/pull/361))
- Enabled pyright strict mode across `src` and refactored internal type checks to use new `TypeGuard` helpers (`is_dict`, `is_mapping`, `is_list`). Added explicit `__all__` lists to public modules to codify existing exports. (by @brendanjryan, [#358](https://github.com/tempoxyz/pympp/pull/358))

## 0.15.1 (2026-10-26)

### Patch Changes

- Added behavior contract tests that pin observable server and client behavior (status codes, problem types, headers, event names, challenge bindings, and offer ordering) before the engine refactor. (by @BrendanRyan, [#340](https://github.com/tempoxyz/pympp/pull/340))

## 0.15.0 (2026-10-25)

### Minor Changes

- Mapped server verification errors to payment errors. `VerificationError` now subclasses `VerificationFailedError`, so invalid credentials return a 402 with a fresh challenge instead of escaping as an unhandled exception. Added `CredentialReplayedError`, a `VerificationError` subclass with status 403 and the `verification-failed` problem type, for Tempo transaction hashes that were already used or are being settled by a concurrent request, and for settled transfers whose memo is bound to another challenge. The `pay` decorator answers it with a final 403 and no `WWW-Authenticate` challenge, so auto-paying clients do not pay again for a payment that already settled. Added `InternalPaymentError` (status 500) for RPC, fee payer and configuration failures, missing receipts, and any non-cancellation failure after a Tempo transaction is broadcast. Its message is generic and the original exception is kept only as `__cause__`. Servers and the MCP transport re-raise it without a retry challenge, so clients are not asked to pay again for a payment that may have landed. (by @BrendanRyan, [#291](https://github.com/tempoxyz/pympp/pull/291))
- Added client-side spend policy to the Tempo charge client. `max_atomic_amount` caps the challenge amount in base units, and `max_amount` caps it in token units using a required `max_amount_decimals`. Caps are validated when the method is created, and a `max_amount` with more significant fractional digits than `max_amount_decimals` is rejected instead of rounded. Caps require an explicit `currency=` or `currencies=` pin, and offers in any other currency are skipped and rejected. `expected_recipients` requires the primary recipient and every split recipient to be in an allowlist (case-insensitive). Offers outside the chain pin, caps or expected recipients are skipped during challenge selection and rejected before signing, using one shared check. (by @BrendanRyan, [#287](https://github.com/tempoxyz/pympp/pull/287))
- Exposed the verified payer as `payer` on `Validation` and on server-side `Receipt`s returned by verification (route handlers, `verify_or_challenge`, `Mpp.broadcast_credential`, and payment success events); it is never serialized into the `Payment-Receipt` header. Tempo charges report the transaction sender for pull-mode credentials and the sender of the matched transfers for hash credentials. Tempo pull-mode credentials that carry a source are now rejected unless the source is on the charge chain and names the transaction sender, fee payer envelopes must be signed by their declared sender, and fee payer co-signing may not change the sender. Added public `parse_pkh_source` and `PkhSource` to `mpp.methods.tempo`. (by @BrendanRyan, [#285](https://github.com/tempoxyz/pympp/pull/285))
- Bound MCP challenges to their receiving tool via a new required `tool` parameter on `create_challenge` and `verify_or_challenge`; the `@pay` decorator derives a stable identity from the handler's module and qualified name unless explicitly overridden. Prevented HTTP clients from retrying payments when caller-supplied credentials are present and blocked post-redirect payment initiation. Returned a terminal 403 for already-succeeded Stripe payments and added an index on SQLite expiry for faster cleanup. (by @BrendanRyan, [#297](https://github.com/tempoxyz/pympp/pull/297))
- Added funding currency detection for hash-based charge receipts by fetching the transaction via `eth_getTransactionByHash` and inspecting its call data. Introduced `_rpc_transaction_calls` and `_calls_funding_currency` helpers to normalize and classify payment routes (direct transfer or token swap), and refactored `_validate_hash` into `_validate_hash_and_sender` to also return the expected sender for the lookup. (by @BrendanRyan, [#333](https://github.com/tempoxyz/pympp/pull/333))
- Add the public `mpp.methods.tempo.attribution` module, exposing `TAG`, `ANONYMOUS`, `encode`, `decode`, `DecodedMemo`, `is_mpp_memo`, `verify_server`, and `verify_challenge_binding` so apps can identify MPP attribution memos on Tempo transfers and reconcile them with the server and Challenge they paid. (by @BrendanRyan, [#286](https://github.com/tempoxyz/pympp/pull/286))
- Added `funding_currency` field to `Receipt` to report the token actually debited to fund a payment. For Tempo pull-mode charges, this reflects the DEX swap input token when an auto-swap route is used, or the charge currency for direct transfers. Updated parsing, formatting, and the `Receipt.success()` factory method to support the new field. (by @BrendanRyan, [#315](https://github.com/tempoxyz/pympp/pull/315))
- Added `allowed_chain_ids` parameter to the `tempo()` factory and `TempoMethod` class, providing a client-side allowlist of chain IDs on which a charge may be paid. Challenges specifying a chain outside the allowlist are skipped during selection and rejected before signing; an empty sequence rejects all charges. (by @BrendanRyan, [#312](https://github.com/tempoxyz/pympp/pull/312))
- Added a required `store` parameter to `MachinePayments.create()` and `TempoPayments` to inject a shared atomic replay store, enabling Tempo charge intents to reject replayed transaction hashes across server replicas. Added validation that the provided store implements `put_if_absent` and updated tests to cover the new replay-protection behavior. (by @BrendanRyan, [#316](https://github.com/tempoxyz/pympp/pull/316))
- Added the `evm` payment method with EIP-3009 authorization support, enabling servers to charge USDC and other EIP-3009 tokens on Base, Celo, and other EVM chains. The method serves both native MPP clients and x402 v2 `exact` clients from a single endpoint, settling through an x402 facilitator or a custom settle hook. Added a new `pympp[evm]` optional extra and pre-defined assets for Base USDC, Base Sepolia USDC, Celo USDC, Celo USDT, and Celo Sepolia USDC. (by @BrendanRyan, [#320](https://github.com/tempoxyz/pympp/pull/320))
- Added support for additional payment receipt metadata fields (`external_id`, `subscription_id`, `funding_currency`, `extra`, and `extensions`) to `MCPReceipt`, with full round-trip serialization and propagation to/from the core `Receipt` type. Extensions are safely filtered to prevent overriding reserved receipt fields during serialization. (by @BrendanRyan, [#330](https://github.com/tempoxyz/pympp/pull/330))
- Added `request_amount` function to allow payment methods to control their wire amount representation via an optional `parse_amount` hook. Methods that define `parse_amount(amount: str) -> str` now own their wire format, while methods without the hook continue to use the existing `parse_units` decimal-to-base-units conversion. (by @BrendanRyan, [#322](https://github.com/tempoxyz/pympp/pull/322))

### Patch Changes

- Fixed challenge expiry enforcement to treat the exact expiry instant as expired by changing strict less-than comparisons (`<`) to less-than-or-equal (`<=`) across all expiry checks. Added a pre-broadcast expiry recheck in Tempo's `ChargeIntent` to prevent settling transactions whose challenges expired during sponsorship or simulation, and introduced a shared `_challenge_expired` helper. Added tests to cover both scenarios. (by @BrendanRyan, [#319](https://github.com/tempoxyz/pympp/pull/319))
- Signed all Tempo charge transactions with expiring nonces, matching the TypeScript SDK. Unsponsored charges previously used the sequential nonce from `eth_getTransactionCount(..., "pending")`, which raced under concurrent payments from one key and ignored a non-zero challenge `nonce_key`. `valid_before` is now capped at the whole second after the challenge expiry, so the transaction stays valid for as long as the challenge does. `FEE_PAYER_VALID_BEFORE_SECS` is deprecated in favor of `EXPIRING_NONCE_VALID_BEFORE_SECS`. Concurrent requests for the same charge challenge and signer now share one in-flight signing. (by @BrendanRyan, [#290](https://github.com/tempoxyz/pympp/pull/290))
- Fixed preservation of challenge `description` field through credential serialization and deserialization. The `description` is now included when converting a `Challenge` to a `ChallengeEcho`, when formatting and parsing authorization headers, and when converting `MCPCredential` to core credentials. (by @BrendanRyan, [#324](https://github.com/tempoxyz/pympp/pull/324))
- Fixed sponsored swap amount validation to constrain swap output tokens, amounts, and approvals during cosigning. Added checks ensuring the swap output token matches the payment currency, the output amount is positive and does not exceed the payment amount, and the approval amount matches the positive maximum swap input. (by @BrendanRyan, [#281](https://github.com/tempoxyz/pympp/pull/281))
- Fixed sponsored transaction validation to require at least 15 seconds of remaining validity before cosigning, ensuring enough time to simulate, broadcast, and include the transaction on-chain. (by @BrendanRyan, [#318](https://github.com/tempoxyz/pympp/pull/318))
- Fixed auth-param name parsing to be case-insensitive per RFC 9110 §11.2, normalizing parameter keys to lowercase before processing. Added tests to verify mixed-case and uppercase parameter names are handled correctly, and that duplicate detection works across different cases. (by @BrendanRyan, [#310](https://github.com/tempoxyz/pympp/pull/310))
- Fixed Stripe credential `externalId` binding so that the request-bound `externalId` is echoed in the credential payload (falling back to the configured value when absent). Added server-side validation that rejects credentials whose `externalId` does not match the route request's `externalId`, raising `InvalidChallengeError` before any Stripe API calls are made. (by @BrendanRyan, [#334](https://github.com/tempoxyz/pympp/pull/334))
- Fixed oversized `Authorization` header values being rejected before the `payment.failed` event could be emitted. Added early size check in `verify_or_challenge` that now routes oversized headers through the `fail` path, ensuring `payment.failed` hooks are triggered with a `MalformedCredentialError`. (by @BrendanRyan, [#308](https://github.com/tempoxyz/pympp/pull/308))
- Parallelized CI by splitting lint/type-check into its own job, added `pytest-xdist` for parallel test execution, and overlapped Docker image pulls with environment setup in the integration job. Also switched package builds to use `uv build` directly. (by @GeorgiosKonstantopoulos, [#303](https://github.com/tempoxyz/pympp/pull/303))
- Updated documentation and code comments to clarify external fee-payer service requirements and responsibilities. Added explicit guidance that external sponsors must independently authorize, validate, simulate, and enforce spending limits before releasing a broadcastable signature, since pympp cannot enforce an external sponsor's policy. (by @BrendanRyan, [#300](https://github.com/tempoxyz/pympp/pull/300))
- Fixed validation in `_encode_transfer_with_memo` to reject non-hex characters in memo values, preventing invalid calldata from being generated for `transferWithMemo` calls. (by @BrendanRyan, [#321](https://github.com/tempoxyz/pympp/pull/321))
- Raised the Authorization credential size limit from 16 KiB to 64 KiB, matching mppx, and applied the size check to the raw header before scheme extraction. Fixed rejections of valid credentials whose size exceeded the old limit due to echoing large challenge requests or `opaque` values. (by @BrendanRyan, [#307](https://github.com/tempoxyz/pympp/pull/307))
- Fixed canonicalization of secp256k1 recovery IDs in Tempo transactions before broadcast, ensuring replay keys and receipt hashes match the node's derived values. Added `_canonical_signature` and `_canonical_raw_transaction` helpers to normalize raw (0/1) recovery IDs to the 27/28 encoding accepted by Tempo nodes. (by @BrendanRyan, [#311](https://github.com/tempoxyz/pympp/pull/311))
- Fixed realm detection to ignore `HOST` and `HOSTNAME` environment variables, preventing container replicas from generating conflicting realm values that would cause credentials to be rejected across replicas. Added tests to verify `HOST`/`HOSTNAME` are ignored and that platform-specific variables (e.g. `RENDER_EXTERNAL_HOSTNAME`) take precedence correctly. (by @BrendanRyan, [#326](https://github.com/tempoxyz/pympp/pull/326))
- Reverted dict body digest to preserve JSON key insertion order instead of sorting keys, aligning behaviour with mppx's `JSON.stringify`. Updated tests to reflect and verify the new insertion-order semantics. (by @BrendanRyan, [#309](https://github.com/tempoxyz/pympp/pull/309))
- Fixed Tempo charge verification to perform a single receipt lookup after definitive broadcast RPC errors, since the node may have included the transaction before its reply failed. Extracted shared receipt verification logic into `_verify_recovered_receipt` and added `_lookup_broadcast_receipt` for the non-ambiguous error path. (by @BrendanRyan, [#317](https://github.com/tempoxyz/pympp/pull/317))
- Added optional `allowed_origins` to `Client` and `PaymentTransport` to reject automatic payments outside configured HTTP(S) origins before credential creation. Origin matching includes scheme and port and preserves arbitrary challenge realms. An empty list denies all payments; omitting the option preserves existing behavior. Use alongside method amount and recipient limits. (by @BrendanRyan, [#296](https://github.com/tempoxyz/pympp/pull/296))
- Tempo charge settlement now waits for the transaction receipt when a synchronous broadcast's outcome is unknown, i.e. the `eth_sendRawTransactionSync` request times out, loses its connection after it was sent, returns an HTTP 5xx, or the node reports the transaction as already pooled. Added a `confirmation_timeout` option to `ChargeIntent` (default 30 seconds, equivalent to mppx's `confirmationTimeoutMs`) that bounds the send and receipt polling together; the send may use at most two thirds of it and its share is passed to the node as the sync timeout. Polling also stops once the transaction's `valid_before` (plus 2 seconds) has passed, after one final receipt lookup so a transaction mined before expiry is still credited. Definitive rejections fail without a receipt lookup, a recovered receipt must match the submitted transaction hash, and when no receipt arrives in time an `InternalPaymentError` is raised with the original broadcast error (or a timeout error if the send never settled) as its cause. Added `paid_retry_timeout` to `PaymentTransport`, `Client` and `request()`, applied only to the paid retry so it can wait out the server's confirmation window: when unset, the inherited read timeout is raised to at least 35 seconds; an explicit value is used exactly, and `None` inherits the timeout unchanged. (by @BrendanRyan, [#289](https://github.com/tempoxyz/pympp/pull/289))
- Fixed replay claims in Redis and SQLite stores to persist independently of any configured TTL, ensuring that a successful `put_if_absent` claim remains protected until explicitly deleted. Added regression tests covering TTL expiry, store reopen, and global cleanup scenarios. (by @BrendanRyan, [#328](https://github.com/tempoxyz/pympp/pull/328))
- Wrapped `rlp.encode` results in `bytes()` calls in test assertions to fix Pyright type compatibility. (by @BrendanRyan, [#290](https://github.com/tempoxyz/pympp/pull/290))
- Fixed companion Transfer and TransferWithMemo events (emitted by TIP-20 for a single token movement) being counted as two separate transfers in split payment verification. Paired events are now deduplicated by token, sender, recipient, and amount before log matching, ensuring routed payments and multi-split receipts are validated correctly. (by @BrendanRyan, [#292](https://github.com/tempoxyz/pympp/pull/292))
- Fixed the client silently returning a 5xx response to a paid retry. `PaymentTransport` now emits `payment.failed` with a `PaymentOutcomeUnknownError` carrying the credential, so callers can reconcile a payment the server may have settled before failing; the response is still returned and never retried. `PaymentOutcomeUnknownError` gains a `transaction_hash` attribute, populated for unsponsored Tempo charges. Before failure hooks run, the 5xx body is buffered up to 64 KiB within 2 seconds so its connection is released; a cut-off body sets `response.extensions["mpp.body_truncated"]`, and a cut-off compressed body is dropped. Cancelling the request while failure hooks run raises `PaymentOutcomeUnknownError` instead of losing the outcome. (by @BrendanRyan, [#288](https://github.com/tempoxyz/pympp/pull/288))
- Preserve the original signed transaction when reconciling sponsored charges across fee-token or sponsor-key changes. Claim recovery records atomically and retain replay protection when confirmed-payment cleanup is cancelled.
- Expire temporary recovery records after the authenticated challenge and transaction inclusion deadlines in the built-in stores without extending retention on retries.
- Redis-backed sponsored recovery now requires Redis server 6.2 or later for atomic absolute expiry. (by @BrendanRyan, [#323](https://github.com/tempoxyz/pympp/pull/323))
- Tempo `ChargeIntent` now logs a one-time (per process) warning when no replay store is configured and it falls back to an in-memory store. Replay protection backed by that store only covers the current process, so multi-worker, multi-replica, or restarting deployments should pass a shared store (e.g. `RedisStore`) via `Mpp.create(store=...)` or `ChargeIntent(store=...)`. (by @BrendanRyan, [#284](https://github.com/tempoxyz/pympp/pull/284))
- Reject zero-amount Tempo charge challenges from an HTTP host other than the challenge realm before signing a transaction. This can affect SDK servers whose default realm is an app name or `localhost`; clients can explicitly pin that realm to its HTTP origin with `trusted_tempo_realms`. MCP clients, which have no HTTP host, require an explicit trusted realm before signing a zero-amount Tempo charge. (by @DerekCofausper, [#306](https://github.com/tempoxyz/pympp/pull/306))
- Forward `meta` through direct `Mpp.charge()` and `Mpp.pay()` verification. HTTP framework scope now includes the request method and preserves configured `_mppx_scope` under `custom` alongside actual framework fields, preventing configured scope from disabling route binding.
- Server-issued challenges include a random HMAC-bound `_mpp_nonce` in opaque metadata even when expiry is fixed. The metadata key is reserved; direct and composed verification preserve application metadata checks. Previously issued nonce-free challenges remain valid only when all other bindings match; low-level `Challenge.create()` remains deterministic. Outstanding HTTP credentials without method binding must obtain a fresh challenge after upgrading.
- Challenge uniqueness does not authenticate the presenter of a stolen complete credential. Bind trusted authenticated account/session context in `meta` when identity matters, and enforce application authorization. A user-supplied payer address is not authentication. Use a shared atomic replay store across processes and replicas.
- This release requires draining payment traffic before an atomic rollout, or version-sticky issuance and retries until outstanding challenges expire. `unique_challenges=False` disables only nonce issuance: it does not preserve old HTTP method scope, custom scope representation, or previously dropped direct metadata. Mixed versions can reject settled hash payments and cause duplicate payment. Nonce-only staging is safe only when every other binding already matches, and retains collision risk during that phase.
- Lifecycle APIs normalize issuance metadata, legacy empty metadata remains accepted, and transient verification errors preserve the authenticated challenge for credential reuse. Invalid-payload errors still issue fresh challenges. Malformed opaque values are rejected by composed verification. Both mapping and scalar custom scopes are preserved in full under `custom`, preventing framework field names from silently discarding application bindings. (by @BrendanRyan, [#305](https://github.com/tempoxyz/pympp/pull/305))
- Fixed a security vulnerability where a split-charge payment leg carrying an MPP attribution memo bound to a different challenge or realm could be used to authorize unintended charges. Now any MPP memo found in matched transfer logs must be bound to the current challenge and realm, or a `CredentialReplayedError` is raised; plain transfers and non-MPP memos remain allowed. (by @BrendanRyan, [#313](https://github.com/tempoxyz/pympp/pull/313))
- Fixed split memos using the MPP attribution format are now rejected before challenge issuance and before client payment, so a fixed split leg can't also pay another challenge. Servers check every Tempo charge issuance path (`Mpp`, `verify_or_challenge`, the `pay` decorator and MCP `create_challenge`), and clients skip such offers during challenge selection. Removed the `fixed` exemption from MPP memo binding checks, so every matched transfer carrying an MPP attribution memo must be bound to the current challenge and realm, matching mppx. Credentials for outstanding challenges with fixed MPP memos fail with `CredentialReplayedError`. (by @BrendanRyan, [#325](https://github.com/tempoxyz/pympp/pull/325))
- Fixed external fee payer sponsor token validation to respect the configured `allowed_fee_tokens` allowlist. Added `_transaction_fee_token` helper to extract the fee token from a signed Tempo transaction and updated `ChargeIntent` to reject sponsored transactions whose fee token is not in the configured allowlist. (by @BrendanRyan, [#314](https://github.com/tempoxyz/pympp/pull/314))
- Preserved the original signed transaction (instead of just the fee token) in the broadcast recovery record, ensuring retries reuse the same sponsored envelope across fee-token or sponsor-key changes. Claimed recovery records atomically using `put_if_absent` and retained replay protection when confirmed-payment cleanup is cancelled. (by @BrendanRyan, [#323](https://github.com/tempoxyz/pympp/pull/323))
- Replaced bare `assert` statements with explicit `ValueError` exceptions in keychain signature validation and `VerifiableWrappedIntent`, providing clearer error messages for invalid `msg_hash` length, malformed `root_account` addresses, and unexpected intent types. Added corresponding tests to cover the new validation paths. (by @BrendanRyan, [#331](https://github.com/tempoxyz/pympp/pull/331))
- Added chain ID verification to Tempo charge settlement. The RPC endpoint's reported chain is now validated against the charge request's advertised chain ID for hash credentials, and serialized transaction payloads are checked to ensure their embedded chain ID matches the charge before processing. (by @ParvAhuja, [7752131](https://github.com/tempoxyz/pympp/commit/7752131))
- Fixed payment method ID parsing to accept the extended charset used by mppx, allowing digits, colons, underscores, and hyphens after a leading lowercase letter (e.g. `tempo-v2`, `vendor:method`, `x402`). Updated tests to reflect the new valid and invalid method ID sets. (by @BrendanRyan, [#327](https://github.com/tempoxyz/pympp/pull/327))

## 0.14.0 (2026-10-12)

### Minor Changes

- Released v0.13.0. Added ordered `currencies` configuration to the Tempo method, enabling servers to accept OUSD first by default on mainnet and Moderato, with improved local fee payer token selection logic and new `OUSD` constant and `default_currencies_for_chain()` helper. Updated the PyJWT pin to 2.15.1 to include upstream security fixes. (by @tempo-github-sts[bot], [#266](https://github.com/tempoxyz/pympp/pull/266))

### Patch Changes

- Stopped requesting cached relay receipts during payment authorization by removing idempotency key headers from broadcast requests. Reused credentials are rejected by relay replay protection, so uncertain outcomes now require separate recovery before executing protected operations. (by @BrendanRyan, [#280](https://github.com/tempoxyz/pympp/pull/280))
- Upgraded `urllib3` dependency from `2.7.0` to `2.8.0` across `tempo`, `stripe`, and `dev` dependency groups. (by @DerekCofausper, [#274](https://github.com/tempoxyz/pympp/pull/274))
- Rejected locally sponsored authorization-bearing transactions before signing when their authorization fields cannot be simulated. (by @BrendanRyan, [#275](https://github.com/tempoxyz/pympp/pull/275))
- Fixed cancelled paid MCP retries to report unknown payment outcomes on both asyncio and Trio, preventing callers from blindly retrying a payment that may have settled. (by @ParvAhuja, [#277](https://github.com/tempoxyz/pympp/pull/277))
- Rejected malformed Unicode in decoded payment headers before verification, returning ordinary parse failures instead of UTF-8 encoding exceptions. Added tests covering lone surrogates in credential fields, nested payloads, and valid supplementary Unicode. (by @BrendanRyan, [#279](https://github.com/tempoxyz/pympp/pull/279))
- Preserved streaming bodies for unmatched 402 responses. Released matched response streams before credential callbacks, closed owned responses on cancellation, and preserved primary errors when cleanup failed. Matched challenges rejected during credential creation now return a readable empty 402 response after their original body has been discarded. (by @BrendanRyan, [#276](https://github.com/tempoxyz/pympp/pull/276))

## 0.13.0 (2026-09-30)

### Minor Changes

- Add ordered `currencies` configuration to the Tempo method. Servers now accept OUSD then USDC.e on Tempo mainnet and OUSD then pathUSD on Moderato by default, issuing one charge Challenge per accepted currency in order; other chains keep their single default currency. An explicit `currencies` list replaces the defaults, and the singular `currency` option, now deprecated for servers, still restricts acceptance to that one currency. Per-request `currency` overrides still issue a single Challenge. Local fee payers no longer pay gas in the charge currency: they use the new `fee_token` option, or else the first token in `allowed_fee_tokens` (default: `fee_tokens_for_chain()`, pathUSD then USDC.e on mainnet) that covers the transaction gas budget, falling back to the first allowed token, so sponsored OUSD charges pay fees in pathUSD or USDC.e. A configured fee token outside the allowed list is rejected. Hosted fee payer URLs are unchanged. Add the `OUSD` constant and `default_currencies_for_chain()`. `default_currency_for_chain()`, fee tokens, and fee payer policies are unchanged, and Stripe's Tempo rail keeps its single USDC.e or pathUSD currency.
- Unsponsored OUSD charges select a funded supported gas token independently of the payment currency. Sponsor token selection skips insufficient dust balances and rounds the maximum gas budget up to microdollars.
- Update the PyJWT pin to 2.15.1 in the Tempo, Stripe, and MCP extras to include upstream security fixes. (by @DerekCofausper, [#265](https://github.com/tempoxyz/pympp/pull/265))

## 0.12.0 (2026-09-26)

### Minor Changes

- Removed custom primary Tempo charge memos. The `memo` charge option and `MethodDetails.memo` field have been removed; clients now always generate attribution memos bound to the challenge and realm, and servers always verify that binding. Split-specific memos remain supported. (by @DerekCofausper, [#251](https://github.com/tempoxyz/pympp/pull/251))
- Remove custom primary Tempo charge memos. Clients always generate attribution memos bound to the challenge and realm, and servers always verify that binding. Remove the `memo` charge option and `MethodDetails.memo`; split-specific memos remain supported. (by @DerekCofausper, [#251](https://github.com/tempoxyz/pympp/pull/251))
- Added `extensions` field to `Receipt` to capture and preserve method-specific top-level fields (e.g. Tempo-specific fields like `challengeId`, `originTxHash`) during parsing and round-tripping of Payment-Receipt headers. (by @mpp-agricola[bot], [#239](https://github.com/tempoxyz/pympp/pull/239))

### Patch Changes

- Fixed Unicode handling in challenge auth-params by encoding non-Latin-1 characters as UTF-16 escapes during serialization and decoding those escapes (including surrogate pairs) during parsing. (by @BrendanRyan, [#256](https://github.com/tempoxyz/pympp/pull/256))
- Added a machine-payment metadata field to every Stripe PaymentIntent created by pympp. (by @bensandler-stripe, [#233](https://github.com/tempoxyz/pympp/pull/233))
- Fixed Stripe idempotent replay detection to reject replayed payments instead of accepting them. Updated both SDK client and raw HTTP paths to raise `VerificationFailedError` when a cached idempotent response is detected via the `Idempotent-Replayed` header. (by @BrendanRyan, [#246](https://github.com/tempoxyz/pympp/pull/246))
- Floor recorded Stripe crypto PaymentIntent amounts to whole cents so fractional-cent on-chain payments are not rounded up. Continue skipping amounts below one cent. (by @DerekCofausper, [#252](https://github.com/tempoxyz/pympp/pull/252))
- Added request-scoped Stripe PaymentIntent options for SPT and Stripe-recorded Tempo payments. (by @staubman-stripe, [#249](https://github.com/tempoxyz/pympp/pull/249))
- Rejected reused Tempo transaction credentials and enabled in-memory replay protection by default. Configure a shared persistent store for deployments with multiple replicas or restarts.
- Bounded the default replay store to 10,000 entries without evicting used hashes, and released reservations after inconclusive receipt lookups so payments can be retried safely. (by @BrendanRyan, [#248](https://github.com/tempoxyz/pympp/pull/248))
- Added a small SPT/Tempo Stripe facade with minimum-aware offers and pinned, attributed Stripe requests, made `spt()` the preferred SPT factory, and deprecated the `stripe()` compatibility name. (by @bensandler-stripe, [#236](https://github.com/tempoxyz/pympp/pull/236))

## 0.11.0 (2026-08-28)

### Minor Changes

- Added a `VerifiableIntent` protocol with separate `validate` and `broadcast` hooks plus bound `Mpp.validate_credential()` and `Mpp.broadcast_credential()` APIs, introduced a `Relay` adapter that delegates Tempo charge validation and finalization to the Tempo API relay (surfacing only safe machine-readable error codes and retryable 402 challenges on decline), and added a runnable `charge-relay` FastAPI example with a payer client. Relay idempotency keys use the `pympp_` namespace, existing Stripe idempotency behavior remains unchanged, and Python validation details use snake_case. (by @ParvAhuja, [#204](https://github.com/tempoxyz/pympp/pull/204))
- Added configurable `max_payment_retries` parameter to `PaymentTransport` and `Client`, allowing callers to override the default retry limit of 3 instead of relying on a hardcoded constant. (by @mpp-agricola[bot], [#223](https://github.com/tempoxyz/pympp/pull/223))

### Patch Changes

- Fixed currency validation during challenge matching by introducing a `_method_accepts_currency` helper that enforces case-insensitive currency comparison when a method has a configured currency constraint. Applied the check in both `PaymentRuntime` and `McpClient` challenge matching and credential creation paths. (by @DerekCofausper, [#232](https://github.com/tempoxyz/pympp/pull/232))
- Added MACH as a supported Tempo charge currency and selected a supported stablecoin with enough balance to cover unsponsored MACH transaction fees. (by @ParvAhuja, [#237](https://github.com/tempoxyz/pympp/pull/237))
- Fixed payment challenge request and opaque serialization to use RFC 8785 JSON Canonicalization Scheme (JCS) via the `rfc8785` library, replacing ad-hoc `json.dumps` calls across HTTP and MCP transports. This ensures challenge IDs are reproducible from the exact bytes emitted on the wire, including non-ASCII characters and JCS number formatting. (by @BrendanRyan, [#235](https://github.com/tempoxyz/pympp/pull/235))
- Fixed initial requests to advertise supported payment methods via the `Accept-Payment` header, derived from the configured payment methods and their intents. Existing `Accept-Payment` headers are preserved when explicitly set by the caller. (by @mpp-agricola[bot], [#225](https://github.com/tempoxyz/pympp/pull/225))
- Fixed `verify_or_challenge` raising `TypeError` when a challenge carried a timezone-naive `expires` value. A naive timestamp parsed successfully but could not be compared to an aware `now`, surfacing as a server error instead of a fail-closed rejection; it is now rejected like any other invalid `expires`. (by @BrendanRyan, [#234](https://github.com/tempoxyz/pympp/pull/234))
- Reverted early termination on repeated actionable challenges, allowing the payment transport to retry payment even when the same challenge ID is received multiple times. (by @mpp-agricola[bot], [#224](https://github.com/tempoxyz/pympp/pull/224))
- Changed Stripe PaymentIntent and Tempo relay idempotency keys to use the SDK-independent `mpp_` prefix while preserving their existing suffix construction. (by @ParvAhuja, [#220](https://github.com/tempoxyz/pympp/pull/220))
- Added a `requires_auth` server option that uses `Payment-Authorization` for Payment credentials so `Authorization` remains available for application authentication. (by @RyanAubrey, [#230](https://github.com/tempoxyz/pympp/pull/230))
- Used the bootstrapped Tempo localnet image for reproducible integration tests, replacing the dynamic `latest` tag pull-and-cache approach with a pinned `tempo-localnet` image digest. Removed the dev-key-based account funding fallback in favour of exclusively using the localnet faucet via `tempo_fundAddress`. (by @BrendanRyan, [#226](https://github.com/tempoxyz/pympp/pull/226))
- Fixed challenge selection to match on both method name and intent, preventing methods from being incorrectly matched to challenges with unsupported intents. Added `intents` property to the `Method` protocol to declare which payment intents each method supports. (by @mpp-agricola[bot], [#216](https://github.com/tempoxyz/pympp/pull/216))

## 0.10.1 (2026-08-09)

### Patch Changes

- Preserved request details across paid retries and rejected payment challenges reached through cross-origin redirects. (by @mpp-agricola[bot], [#214](https://github.com/tempoxyz/pympp/pull/214))
- Fixed handling of fresh 402 payment challenges returned after a paid retry, enabling clients to recover from failed verification and complete multi-round payment flows. Introduced a retry loop with a maximum attempt limit to support these sequential challenge-response exchanges. (by @mpp-agricola[bot], [#214](https://github.com/tempoxyz/pympp/pull/214))

## 0.10.0 (2026-08-03)

### Minor Changes

- Added a transport-neutral `PaymentRuntime` class that provides reusable primitives for matching payment challenges and creating credentials without depending on HTTPX. Refactored `PaymentTransport` and `Client` to accept either a `methods` list or a pre-built `runtime` instance, and consolidated the `Method` protocol into `mpp.runtime`. (by @ParvAhuja, [#202](https://github.com/tempoxyz/pympp/pull/202))
- Add `hint` field to `PaymentError` problem details. `PaymentRequiredError`, `MalformedCredentialError`, and `PaymentMethodUnsupportedError` now include a default hint pointing users to wallet documentation. (by @ParvAhuja, [#202](https://github.com/tempoxyz/pympp/pull/202))
- Improved HTTP challenge parsing to correctly split merged `WWW-Authenticate` headers with quoted commas, added pass-through support for streaming request bodies on ordinary and unrelated 402 responses, and introduced `PaymentOutcomeUnknownError` (consolidated from the MCP client into core) to surface explicit errors when a paid retry outcome is uncertain due to network failures or task cancellation. (by @ParvAhuja, [#202](https://github.com/tempoxyz/pympp/pull/202))

### Patch Changes

- Added Python 3.14 to the list of declared supported versions in package classifiers and added Python 3.11 to the CI test matrix. (by @ParvAhuja, [#202](https://github.com/tempoxyz/pympp/pull/202))
- Preserved MCP challenge metadata when converting MCP challenges to core payment challenges. (by @ParvAhuja, [#202](https://github.com/tempoxyz/pympp/pull/202))
- Prevent the optional MCP SDK from resolving to incompatible 2.x releases. (by @ParvAhuja, [#202](https://github.com/tempoxyz/pympp/pull/202))
- Handle multipart (`files=`) and streaming bodies on paid 402 retry. Multipart bodies are buffered and replayed identically; async generator bodies raise `PaymentError` before any I/O. (by @ParvAhuja, [#202](https://github.com/tempoxyz/pympp/pull/202))
- Preserve `subscriptionId` when parsing and formatting payment receipts. (by @ParvAhuja, [#202](https://github.com/tempoxyz/pympp/pull/202))
- Fixed MCP payment error detection to support the current MCP SDK's `McpError` shape, where error code and data are nested under an `error` attribute rather than directly on the exception. Added helper functions `_error_code` and `_error_data` to extract these fields from both error shapes. (by @ParvAhuja, [#202](https://github.com/tempoxyz/pympp/pull/202))

## 0.9.1 (2026-07-01)

### Patch Changes

- Fixed rejection of ABI-encoded calldata with trailing padding bytes in Tempo transfer, approve, and swap calls. Added exact-length validation constants and updated `_match_single_transfer_calldata`, `_match_transfer_calldata`, and `_validate_call_scope` to reject any calldata that does not match the expected byte length precisely. (by @BrendanRyan, [#160](https://github.com/tempoxyz/pympp/pull/160))

## 0.9.0 (2026-06-23)

### Minor Changes

- Validate the credential `source` on the Tempo hash-credential verification path. The server now parses the `did:pkh:eip155` source before reserving the transaction hash, requires TIP-20 transfers to originate from the declared source address (falling back to the receipt sender when no source is provided), and rejects malformed or chain-mismatched sources with a uniform error. Adds a `validate_sender` callback (with `SenderValidation` / `ValidateSender`) to `ChargeIntent` to authorize smart-account / relayer flows where the on-chain transfer sender differs from the declared source. (by @stevencartavia, [#154](https://github.com/tempoxyz/pympp/pull/154))
- Sponsored (fee-payer) charges now dry-run the co-signed transaction via `tempo_simulateV1` before broadcasting. If the transaction would revert on-chain, the sponsor rejects it instead of paying gas for a failing transaction. The check fails closed: if the simulation RPC is unavailable, the charge is rejected. (by @stevencartavia, [#154](https://github.com/tempoxyz/pympp/pull/154))

### Patch Changes

- Preserve all sender-signed fields when decoding and re-signing fee-payer (0x78) envelopes. Two fields that are part of the sender's signing hash were being lost when the fee payer reconstructed the transaction to cosign it, causing valid transactions to be rejected ("Sender address does not match recovered signer") or mis-attributed:
- **`keyAuthorization`**: the decoder rebuilt it from only `chain_id`, `key_type`, `key_id`, and `expiry`, dropping `limits` and the T6 (TIP-1049) `allowed_calls`, `witness`, `is_admin`, and `account` fields. It now round-trips the authorization RLP verbatim (decode and encode), so it works for both legacy and T6 authorizations — including non-secp256k1 root signatures — without requiring a T6-aware `pytempo`.
- **`tempo_authorization_list`**: was dropped entirely during cosigning; it is now carried through.
- Access-key (keychain) and other non-secp256k1 sender signatures, which a fee payer cannot verify offline, are now rejected with a clear error instead of an opaque ECDSA recovery failure, and the envelope decoder fails closed on unexpected field counts.
- Pre-broadcast simulation (`tempo_simulateV1`) is skipped for locally co-signed transactions that carry a `keyAuthorization` or a non-empty `tempo_authorization_list`. These fields are preserved verbatim as opaque RLP for the broadcast transaction but cannot yet be faithfully re-serialized into the simulation JSON (`keyAuthorization` / `aaAuthorizationList`), so the transaction is broadcast without the extra revert check rather than simulated as a different transaction. (by @stevencartavia, [#154](https://github.com/tempoxyz/pympp/pull/154))

## 0.8.2 (2026-06-02)

### Patch Changes

- Hardened Tempo transaction credential verification by enforcing challenge-bound attribution memos and reserving transaction hashes before broadcast to avoid duplicate rebroadcasts. (by @EmmaJamieson-Hoare, [#144](https://github.com/tempoxyz/pympp/pull/144))

## 0.8.1 (2026-06-01)

### Patch Changes

- Added strict validation for payment method IDs, requiring them to match `1*LOWERALPHA` (lowercase letters only). Updated `Receipt` default method from empty string to `"tempo"` and fixed test fixtures to use valid method IDs. (by @EmmaJamieson-Hoare, [#142](https://github.com/tempoxyz/pympp/pull/142))

## 0.8.0 (2026-05-16)

### Minor Changes

- Added client and server payment lifecycle hooks (`EventDispatcher`, `PaymentEvent`) for observing challenge selection, credential creation, payment responses, successes, and failures. Both `PaymentTransport`/`Client` and `Mpp`/`pay` now expose typed `on_*` registration methods with unsubscribe callbacks. (by @BrendanRyan, [#140](https://github.com/tempoxyz/pympp/pull/140))

## 0.7.0 (2026-05-01)

### Minor Changes

- Added fee payer policy enforcement for sponsored Tempo transactions, validating gas limits, fee caps, total fee budgets, validity windows, and access lists against per-chain policy defaults. Added call pattern validation to restrict sponsored transactions to approved selectors (transfers, and optionally an approve+swap prefix via the stablecoin DEX). (by @BrendanRyan, [#135](https://github.com/tempoxyz/pympp/pull/135))

### Patch Changes

- Fixed client chain policy enforcement to reject challenges that attempt to switch the client to a different chain. Clients pinned to a chain (via `chain_id` or `rpc_url`) now raise a `ValueError` immediately instead of silently following the challenge's `chainId`. (by @BrendanRyan, [#135](https://github.com/tempoxyz/pympp/pull/135))

## 0.6.3 (2026-04-22)

### Patch Changes

- Allowed Tempo pull-mode validation to accept client attribution memos in both preflight calldata checks and split receipt matching while still rejecting truncated `transferWithMemo` calldata. (by @BrendanRyan, [#130](https://github.com/tempoxyz/pympp/pull/130))

## 0.6.2 (2026-04-19)

### Patch Changes

- Defaulted `chain_id` to 4217 (mainnet) in the `tempo()` function, removing the need to pass it explicitly. Removed the hardcoded testnet fee payer URL fallback, requiring explicit fee payer configuration on mainnet. Updated tests and docs accordingly. (by @BrendanRyan, [#127](https://github.com/tempoxyz/pympp/pull/127))
- Defaulted `chain_id` to 4217 (mainnet) in the `tempo()` function, removing the need to pass it explicitly. Updated docs and example code accordingly. (by @BrendanRyan, [#127](https://github.com/tempoxyz/pympp/pull/127))
- Fixed `decode_fee_payer_envelope` to return a `SignedKeyAuthorization` object instead of raw RLP bytes when a key authorization is present in the fee payer envelope. (by @BrendanRyan, [#127](https://github.com/tempoxyz/pympp/pull/127))

## 0.6.1 (2026-04-09)

### Patch Changes

- Cached Tempo chain IDs per RPC URL to avoid redundant `eth_chainId` calls. Also parallelized `eth_getTransactionCount` and `eth_gasPrice` fetches using `asyncio.gather`. (by @BrendanRyan, [#115](https://github.com/tempoxyz/pympp/pull/115))
- Replaced `eth_sendRawTransaction` + polling loop with `eth_sendRawTransactionSync` in Tempo's verify flow, eliminating the separate receipt polling step and extracting the transaction hash directly from the receipt response. (by @BrendanRyan, [#115](https://github.com/tempoxyz/pympp/pull/115))

## 0.6.0 (2026-04-07)

### Minor Changes

- Added split payments support for Tempo charges, allowing a single charge to be split across multiple recipients. Port of [mpp-rs PR #180](https://github.com/tempoxyz/mpp-rs/pull/180). (by @BrendanRyan, [#104](https://github.com/tempoxyz/pympp/pull/104))
- Added Stripe payment method (`mpp.methods.stripe`) supporting the Shared Payment Token (SPT) flow for HTTP 402 authentication. Includes client-side `StripeMethod` and `stripe()` factory, server-side `ChargeIntent` for PaymentIntent verification via Stripe SDK or raw HTTP, Pydantic schemas, and a `stripe` optional dependency group. (by @BrendanRyan, [#104](https://github.com/tempoxyz/pympp/pull/104))
- Added split payments support for Tempo charges, allowing a single charge to be split across multiple recipients. Port of [mpp-rs PR #180](https://github.com/tempoxyz/mpp-rs/pull/180). (by @BrendanRyan, [#104](https://github.com/tempoxyz/pympp/pull/104))

## 0.5.4 (2026-04-03)

### Patch Changes

- Fixed Tempo attribution memos to be deterministically bound to challenge IDs using a keccak256-derived nonce instead of random bytes. Added `verify_challenge_binding` to enforce that verified payments carry a memo matching the specific challenge being redeemed. (by @BrendanRyan, [#111](https://github.com/tempoxyz/pympp/pull/111))

## 0.5.3 (2026-04-01)

### Patch Changes

- Defaulted `chain_id` to 4217 (mainnet) in the `tempo()` function, removing the need to pass it explicitly. Updated docs and example code accordingly. (by @BrendanRyan, [#108](https://github.com/tempoxyz/pympp/pull/108))
- Added Python 3.11 support by lowering the `requires-python` constraint from `>=3.12` to `>=3.11`, updating tooling targets accordingly, and replacing PEP 695 generic syntax with `TypeVar` for compatibility. (by @BrendanRyan, [#108](https://github.com/tempoxyz/pympp/pull/108))

## 0.5.2 (2026-04-01)

### Patch Changes

- Fixed optional dependency handling by converting eager imports in `mpp.extensions.mcp` and `mpp.methods.tempo` to lazy `__getattr__`-based loading, so importing these modules without their extras installed no longer raises `ImportError` at import time. Added clear install hint messages when optional attrs are accessed without the required extras, and added `eth-account`, `eth-hash`, `attrs`, and `rlp` as declared dependencies for the `[tempo]` extra. (by @BrendanRyan, [#105](https://github.com/tempoxyz/pympp/pull/105))

## 0.5.0 (2026-03-30)

### Minor Changes

- Added access key signing support for Tempo transactions. When `root_account` is set, nonce and gas estimation now use the root account (smart wallet) address, transactions are signed via `sign_tx_access_key`, and the credential source reflects the root account rather than the access key address. (by @BrendanRyan, [#103](https://github.com/tempoxyz/pympp/pull/103))
- Added `RedisStore` and `SQLiteStore` backends to `mpp.stores` for replay protection, with optional extras (`pympp[redis]`, `pympp[sqlite]`). Added `store` parameter to `Mpp.__init__` and `Mpp.create()` that automatically wires the store into intents supporting replay protection. (by @BrendanRyan, [#103](https://github.com/tempoxyz/pympp/pull/103))

### Patch Changes

- Raised test coverage by adding tests for edge cases across charge, parsing, server, and store modules, and updated CI to generate and upload XML/HTML coverage reports for Python 3.12. (by @BrendanRyan, [#103](https://github.com/tempoxyz/pympp/pull/103))
- Fixed fail-closed expiry enforcement in `ChargeIntent.verify`: requests with a missing `expires` challenge parameter are now rejected instead of silently allowed through. (by @BrendanRyan, [#103](https://github.com/tempoxyz/pympp/pull/103))

## 0.4.2 (2026-03-20)

### Patch Changes

- Added atomic `put_if_absent` method to `Store` protocol and `MemoryStore`, replacing the racy `get()`/`put()` pattern for charge replay protection. Normalized transaction hashes to lowercase before dedup to prevent mixed-case bypasses. (by @BrendanRyan, [#91](https://github.com/tempoxyz/pympp/pull/91))

## 0.4.1 (2026-03-18)

### Patch Changes

- Updated the testnet escrow contract address to `0xe1c4d3dce17bc111181ddf716f75bae49e61a336`. (by @BrendanRyan, [#90](https://github.com/tempoxyz/pympp/pull/90))
- Updated `examples/api-server/README.md` to replace references to the external `purl` tool with the `pympp` client (`python -m mpp.fetch`) and corrected the `secret_key` documentation to reflect that it is read from the `MPP_SECRET_KEY` env var rather than auto-generated. (by @BrendanRyan, [#90](https://github.com/tempoxyz/pympp/pull/90))
- Added a pluggable `Store` interface and `MemoryStore` implementation for transaction hash replay protection in `ChargeIntent`. When a store is provided, verified tx hashes are recorded and subsequent attempts to reuse the same hash are rejected with a `VerificationError`. (by @BrendanRyan, [#90](https://github.com/tempoxyz/pympp/pull/90))
- Updated mainnet escrow contract address to `0x33b901018174DDabE4841042ab76ba85D4e24f25`. (by @BrendanRyan, [#90](https://github.com/tempoxyz/pympp/pull/90))
- Raised `DEFAULT_GAS_LIMIT` from 100,000 to 1,000,000 for Tempo AA (type-0x76) transactions to account for their higher intrinsic gas cost (~270k for a single TIP-20 transfer). (by @BrendanRyan, [#90](https://github.com/tempoxyz/pympp/pull/90))

## 0.4.0 (2026-03-06)

### Minor Changes

- Require explicit server secret key — remove implicit `.env` auto-generation/persistence. `MPP_SECRET_KEY` must be set in the environment or `secret_key` passed explicitly; whitespace-only values are rejected. Preserves `__wrapped__` on payment decorators. Aligns pympp with mpp-rs and mppx behavior. (by @BrendanRyan, [#81](https://github.com/tempoxyz/pympp/pull/81))
- Consolidated `expires` from the request body into the challenge-level `expires` auth-param exclusively. Removed `expires` as a field from `ChargeRequest` schema and updated all server, intent, and test code to read expiry from `credential.challenge.expires` instead. (by @BrendanRyan, [#81](https://github.com/tempoxyz/pympp/pull/81))
- Added `digest` and `opaque` fields to `MCPChallenge` for extended challenge metadata propagation. Fixed deterministic body digest computation by adding `sort_keys=True` to JSON serialization, and corrected ISO 8601 timestamp formatting. Added cross-realm attack prevention by validating echoed challenge fields (`realm`, `method`, `intent`) against server-expected values in both HTTP and MCP transports. (by @BrendanRyan, [#81](https://github.com/tempoxyz/pympp/pull/81))

### Patch Changes

- Applied `transform_request` method hook in `Mpp.charge` and `Mpp.pay` helpers, ensuring the method's request transform is called before verification. Added tests covering both helpers. (by @BrendanRyan, [#81](https://github.com/tempoxyz/pympp/pull/81))
- Updated documentation URLs from `machinepayments.dev` to `mpp.dev`, updated the IETF draft reference link, removed the `currency` parameter from the README example, updated the example API endpoint, and updated the package description in `pyproject.toml`. (by @BrendanRyan, [#81](https://github.com/tempoxyz/pympp/pull/81))
- Added server-side expiry enforcement to reject replayed credentials after their challenge has expired. (by @BrendanRyan, [#81](https://github.com/tempoxyz/pympp/pull/81))

## 0.3.0 (2026-02-23)

### Minor Changes

- Added extensive test coverage for memo-based transfers, including unit tests for `_match_transfer_calldata` and `_verify_transfer_logs` with memo fields, integration tests for end-to-end charge flows with server-specified memos, and new test modules for body digest computation, error types, expires helpers, and keychain signature handling. (by @BrendanRyan, [#70](https://github.com/tempoxyz/pympp/pull/70))
- Added 0x78 fee payer envelope encoding/decoding module with `encode_fee_payer_envelope` and `decode_fee_payer_envelope` functions. Updated `ChargeIntent._cosign_as_fee_payer` to use the new 0x78 wire format instead of 0x76, including sender address verification against the recovered signer. Exported `USDC`, `PATH_USD`, and `default_currency_for_chain` from the tempo package public API. (by @BrendanRyan, [#70](https://github.com/tempoxyz/pympp/pull/70))
- Added chain-specific default currency selection: mainnet now defaults to USDC and testnet defaults to pathUSD. Exported `USDC`, `PATH_USD`, and `default_currency_for_chain` from the tempo package public API. Updated tests to reflect the new default currency behavior. (by @BrendanRyan, [#70](https://github.com/tempoxyz/pympp/pull/70))

### Patch Changes

- Added pyright, build, and twine as dev dependencies. Improved CI pipeline with separate lint, test, and package jobs, concurrency cancellation, coverage enforcement, and package validation. Fixed pyright type errors with `type: ignore` annotations and refactored `ChargeIntent` to use a `_get_rpc_url()` helper to safely unwrap the optional RPC URL. (by @BrendanRyan, [#70](https://github.com/tempoxyz/pympp/pull/70))

## 0.2.0 (2026-02-20)

### Minor Changes

- Added `opaque`/`meta` field support for server-defined correlation data in challenges. The `meta` parameter on `Challenge.create()` and `verify_or_challenge()` stores arbitrary string key-value pairs as an HMAC-bound `opaque` field, included in challenge IDs and serialized in `WWW-Authenticate` and `Authorization` headers. (by @BrendanRyan, [#68](https://github.com/tempoxyz/pympp/pull/68))
- Added full fee payer support to the Tempo method, allowing servers to co-sign sponsored transactions locally using a configured `fee_payer` account instead of forwarding to an external service. Updated the `tempo()` factory and `ChargeIntent` to propagate the fee payer account, and introduced expiring nonce logic for replay protection on sponsored transactions. (by @BrendanRyan, [#68](https://github.com/tempoxyz/pympp/pull/68))
- Added chain-specific default currency selection: mainnet now defaults to USDC and testnet defaults to pathUSD. Exported `USDC`, `PATH_USD`, and `default_currency_for_chain` from the tempo package public API. Updated tests to reflect the new default currency behavior. (by @BrendanRyan, [#68](https://github.com/tempoxyz/pympp/pull/68))

### Patch Changes

- Reordered `_REALM_ENV_VARS` list alphabetically and added `FLY_APP_NAME`, `HEROKU_APP_NAME`, and `WEBSITE_HOSTNAME` environment variables for realm detection. (by @BrendanRyan, [#68](https://github.com/tempoxyz/pympp/pull/68))

## 0.1.5 (2026-02-18)

### Patch Changes

- chore: remove release environment requirement from publish workflow (by @BrendanRyan, [#58](https://github.com/tempoxyz/pympp/pull/58))

## 0.1.4 (2026-02-18)

### Patch Changes

- Moved `VerificationError` from `mpp.server.intent` to `mpp.errors` so that client-only imports no longer transitively load server dependencies. Added a re-export shim in `mpp.server.intent` for backwards compatibility and added import isolation tests to enforce the invariant. (by @BrendanRyan, [#55](https://github.com/tempoxyz/pympp/pull/55))
- Sorted imports to satisfy ruff I001 linting rules in `src/mpp/methods/tempo/intents.py`. (by @BrendanRyan, [#55](https://github.com/tempoxyz/pympp/pull/55))

## 0.1.3 (2026-02-18)

### Patch Changes

- fix: accept `transferWithMemo` calls in pre-broadcast validation when no explicit memo is required
- Aligns with mppx behavior — clients may auto-generate attribution memos via `transferWithMemo` even when the server request has no explicit memo. Previously, the server would reject these with `VerificationError: Invalid transaction: no matching payment call found`. (by @BrendanRyan, [#52](https://github.com/tempoxyz/pympp/pull/52))

## 0.1.2 (2026-02-17)

### Patch Changes

- Fixed PyPI publish workflow by using Python 3.12 for building (package requires >=3.12). (by @BrendanRyan, [#46](https://github.com/tempoxyz/pympp/pull/46))

## 0.1.1 (2026-02-17)

### Patch Changes

- Test publish to verify end-to-end PyPI release pipeline. (by @BrendanRyan, [#44](https://github.com/tempoxyz/pympp/pull/44))

## 0.1.0 (2026-02-17)

### Minor Changes

- Added HMAC-bound challenge IDs for stateless MCP transport security and support for optional description/externalId fields in ChargeRequest. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Renamed `@requires_payment` decorator to `@pay` across the codebase, including all documentation, examples, and tests. Added `server.pay()` decorator method on `Mpp` class. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Removed streaming payment support from the Tempo payment method. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))

### Patch Changes

- Switched pytempo dependency from git reference to PyPI package version. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Fixed conformance issues by rejecting duplicate authentication parameters and requiring the `method` field in payment receipts. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Added `sort_keys=True` to all `json.dumps()` calls to ensure JCS (RFC 8785) canonical JSON serialization when generating challenge IDs and credentials. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Switched payment token from AlphaUSD to PathUSD by updating currency address from `0x20c0000000000000000000000000000000000001` to `0x20c0000000000000000000000000000000000000` and removed deprecated `ALPHA_USD` constant. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))

## `pympp@0.0.1`

### Patch Changes

**Breaking:** `tempo()` now requires an explicit `intents` parameter. The implicit `ChargeIntent` default has been removed. (by @BrendanRyan, [#26](https://github.com/tempoxyz/pympp/pull/26))
- Initial release of pympp - HTTP 402 Payment Authentication for Python. (by @BrendanRyan, [#26](https://github.com/tempoxyz/pympp/pull/26))
