# Changelog

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

