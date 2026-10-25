# Coverage report

Functional coverage of pympp against the TypeScript reference SDK
[mppx](https://github.com/wevm/mppx) (`13a90352`, package 0.13.5), for the scope of this
release. Measured on 2026-10-25.

Legend: ✅ implemented with the same behaviour · ⚠️ implemented with a deliberate difference
(stated) · ❌ not implemented (reason given).

The tables below summarize the detailed feature-by-feature evidence in
[docs/parity/](parity/).

- [Scope](#scope)
- [Areas](#areas): [core](#core-primitives), [server](#server-engine), [client](#client-engine),
  [Tempo charge](#tempo-charge), [Stripe](#stripe), [EVM and x402](#evm-and-x402), [MCP](#mcp)
- [Key differences from mppx](#key-differences-from-mppx)
- [Verification](#verification): [tests](#tests), [conformance](#conformance)
- [Planned feature PRs](#planned-feature-prs)
- [Known gaps](#known-gaps)

## Scope

This release is the interface refactor of pympp: it moves pympp onto mppx's engine model and
covers what pympp 0.15.0 already offers, with the fixes released in 0.15 ported. Features beyond
that come back as separate pull requests (see [Planned feature PRs](#planned-feature-prs)).

| Area | pympp 0.15 feature | Status | Tests |
|---|---|---|---|
| Core primitives | Challenge, Credential, Receipt, request codec, body digest, expiry, errors, `Accept-Payment`, stores (memory, Redis) | ✅ | 352 |
| Server engine | `Mpp` route handlers, compose, events, `requires_auth`, validate/broadcast, Starlette/FastAPI decorator | ✅ / ⚠️ framework adapter | 183 |
| Client engine | Payment-aware `httpx` transport, retries, events, `allowed_origins`, manual flows | ✅ / ⚠️ no global fetch | 104 |
| Tempo charge | Hash, transaction and proof Credentials, splits, attribution memos, local and remote fee sponsorship, relay, confirmation and recovery, client spend policy, access keys | ✅ / ⚠️ RPC client model | 813 |
| Stripe | SPT charge, `paymentIntentOptions`, machine payments (SPT + Tempo rails, deposit addresses, crypto payment recording) | ✅ / ⚠️ client adapter protocol | 147 |
| EVM and x402 | EIP-3009 charge (client and server), serving x402 v2 `exact` clients on the same route, facilitator client, x402 client protocol | ✅ | 211 |
| MCP | Paid tools, paying client, payment capabilities | ✅ / ⚠️ official SDK 2.x wrapper, per-tool binding | 55 |

Conformance (`mpp-tools` `6eb9b98`, vectors and flows unchanged): **vectors 153/153, flows
34/34, server verification 9/9**. Test suite: **1865 passed** (1868 collected, 3 conformance
wrappers deselected).

## Areas

### Core primitives

| mppx feature | Status | Notes |
|---|---|---|
| `Challenge` (serialize/deserialize, merged `WWW-Authenticate` lists, HMAC id, `verify`, `meta`/`opaque`, `digest`, `header`, `expires`, size limits) | ✅ | Frozen dataclass. `Challenge.protocol` is a non-wire tag for x402. |
| `Credential` (`Authorization: Payment`, `Payment-Authorization`, `source`) | ✅ | |
| `Receipt` (base fields, `externalId`, `subscriptionId`, `fundingCurrency`, extension fields) | ✅ | Extension fields live in `Receipt.extra`. |
| `PaymentRequest` (base64url of JCS), `BodyDigest`, `Expires`, `Constants` | ✅ | JCS is built in (no `rfc8785` dependency). |
| `Errors` (types, titles, statuses, hints, problem details) | ✅ | Constructors are keyword-only. |
| `Method.from` / `toClient` / `toServer` | ⚠️ | Split into `Method` (pydantic models), `ClientMethod` and `ServerMethod` (hook dataclasses). zod transforms become pydantic validators/serializers. |
| `Store` (`memory`, `redis`, `upstash`, `cloudflare`, `from`, `tryClaim`) | ⚠️ | `memory()`, `redis()` (also covers Upstash/Valkey over the Redis protocol), `kv()` (Cloudflare-style string KV), `prefixed()`, `try_claim()`. |
| `Mcp` constants and shapes | ✅ | `mpp.mcp` |
| `AcceptPayment` header (parse, q-values, preferences, ordering) | ✅ | |
| Env realm / secret detection | ✅ | Same variable list as mppx. |
| `z` (zod re-export) | ❌ | Not applicable. pydantic is used directly. |

### Server engine

| mppx feature | Status | Notes |
|---|---|---|
| `Mppx.create` (methods, realm, secretKey ≥ 32 bytes, requiresAuth, transport) | ✅ | `mpp.server.Mpp(...)` |
| Handlers by key, namespace, intent shorthand (implicit compose), aliases | ✅ | `mpp["tempo/charge"]`, `mpp.tempo.charge`, `mpp.charge` |
| `compose` (instance and module level, nested), `challenge.*`, `verifyCredential` / `validateCredential` / `broadcastCredential` | ✅ | |
| Method lifecycle hooks (`request`, `authorize`, `preflight`, `respond`, `canOffer`, `onPaymentSuccess`, `stableBinding`, `validate`/`broadcast`/`verify`) | ✅ | One frozen context dataclass per hook. Sync or async. |
| Events (`challenge.created`, `payment.success`, `payment.failed`, `*`; snapshots; set semantics) | ✅ | Payloads are frozen dataclasses. |
| Route scope binding, realm resolution, default 5-minute expiry, digest binding, replay 403 without challenge | ✅ | |
| Transports `http`, `mcpSdk` | ✅ | Generic `Transport[...]` ABC |
| `Request` / `Response` helpers | ⚠️ | Framework-neutral `mpp.server.Request`/`Response` (`httpx.Headers`, bytes or async-iterable bodies). |
| `NodeListener`, `express`, `hono`, `nextjs`, `elysia` middlewares | ⚠️ | Replaced by `mpp.server.starlette` (`paid`, `to_request`, `to_starlette`) for Starlette and FastAPI. |

### Client engine

| mppx feature | Status | Notes |
|---|---|---|
| `Mppx.create` (methods, transport, onChallenge, orderChallenges, paymentPreferences, acceptPaymentPolicy) | ✅ | `mpp.client.Mpp(...)` |
| Payment-aware `fetch` (402 retry, redirect rules, credential header purge, 402 body release, outcome-unknown on abort, `payment.response` tee) | ⚠️ | Built on `httpx`: `mpp.fetch()`, `mpp.client()`, `mpp.payment_transport`. Cancellation replaces `AbortSignal`. |
| `polyfill` / `restore` (global fetch patching) | ❌ | Python has no global fetch, and the SDK never patches `httpx`. |
| Transport `http`; protocols `mpp`, `x402` | ✅ | `mpp.client.Protocol` for custom protocols |
| `createCredential`, prepared payments/requests | ✅ | `create_credential`, `prepare_payment`, `prepare_request` |
| `MethodChallenge` / `MethodResponse` | ✅ | `ClientMethod.prepare` / `handle_response` |
| Client events (`challenge.received` may return a credential, `credential.created`, `payment.response`, `payment.failed`, `*`) | ✅ | |
| Origin allowlist (pympp `allowed_origins`, not in mppx) | ✅ (added) | `Mpp(allowed_origins=[...])`. A 402 from another origin (checked on the URL that returned it) is returned unchanged: no credential, no events. |

### Tempo charge

Details: [parity/tempo-charge.md](parity/tempo-charge.md). Transactions and signing are built on
pytempo; envelopes, signatures and key authorizations are byte-compatible with ox/viem
(`tests/tempo/foundations`, 360 tests).

| mppx feature | Status | Notes |
|---|---|---|
| Ordered currency offers (`tempo.charge`, `tempo()`), `currencies`, deprecated `currency` | ✅ | Factories return `list[ServerMethod]`. |
| Hash (push), transaction (pull) and zero-amount proof credentials; memo/attribution binding; splits; replay claims | ✅ | |
| Local and remote fee sponsorship; sponsor policy; `allowedFeeTokens`, `feeToken` | ✅ | |
| Confirmation and recovery (sync broadcast, ambiguous errors, receipt polling, `waitForConfirmation: false`) | ✅ | Plus pympp 0.15's sponsored-submission recovery records. |
| Relay (`/v1/mpp/validate` + `/broadcast`) | ✅ | |
| RPC retries (viem `http` transport rules; broadcasts never retried) | ✅ | |
| Client policy (chains, recipients, currencies, max amounts), `resolveAccount`, access keys, `transactionHash` | ✅ | |
| viem client with a static chain (`Client not configured with chainId X`) | ⚠️ | `RpcClient` has no static chain. The chain is read once via `eth_chainId` and cached. |

### Stripe

Details: [parity/stripe.md](parity/stripe.md).

| mppx feature | Status | Notes |
|---|---|---|
| Charge schema, `parseUnits`, client (`createToken`, `externalId`, payment method), server (PaymentIntent creation, idempotency, `requires_action`, minimums, externalId binding) | ✅ | |
| `paymentIntentOptions` | ⚠️ | Request-scoped only, matching mppx's runtime. The factory rejects it with `TypeError`. |
| Analytics metadata, record payment, deposit addresses | ✅ | `mpp_sdk` reports `pympp/<version>`. |
| `stripe.create()` machine payments (SPT and Tempo charge rails, default methods, custom rails) | ⚠️ | snake_case names. `load_default_methods()` is async, because mppx's sync-or-thenable return has no Python analog. |
| Stripe Node SDK client duck typing | ⚠️ | Python protocols (`StripeClient`, `StripeRawClient`), both implemented by the built-in `StripeHttpClient`. |
| Live Stripe integration test | ❌ | Needs a real Stripe key. |

### EVM and x402

Details: [parity/evm-x402.md](parity/evm-x402.md).

| mppx feature | Status | Notes |
|---|---|---|
| `evm/charge` schema, client (policy checks, EIP-3009 signing, deferred signer), server (validate/broadcast, `settle`, facilitator), `evm({currencies})` offers, assets, chains | ✅ | Plus pympp 0.15's settlement hardening (replay claims, validity cap, no retry challenge when funds may have moved). |
| x402 v2 wire types, header codecs, route-binding nonce, client protocol, exact scheme, facilitator client | ✅ | Challenge brand → `Challenge.protocol == "x402"`. |
| x402 serving on the EVM charge route (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`, route binding) | ✅ | `mpp.evm.server.charge(x402=X402Options(...))` |
| viem `tokens` and accounts | ⚠️ | `mpp.evm.tokens.Token`. Signers are a `TypedDataSigner` protocol; `eth_account` accounts work directly. |
| Deprecated `evm({currency})` / client `assets` alias | ❌ | No compatibility shims. |
| Spec credential types `permit2`, `transaction`, `hash` | ❌ | mppx implements only `authorization`, and parity wins. |
| `Facilitator.unwrapFetch` | ❌ | Not needed (no global fetch patching). |

### MCP

Details: [parity/mcp.md](parity/mcp.md).

| mppx feature | Status | Notes |
|---|---|---|
| `Transport.mcpSdk()` (meta credentials, `McpError` challenges, error codes, receipts in `_meta`), compose | ✅ | `mpp.mcp_sdk.server.mcp_sdk()`. Raises `MCPError` from the official SDK 2.x. |
| Per-tool challenge binding | ⚠️ | Deliberate: challenges are bound to `tool:<name>` of the called tool, and an explicit `scope=` wins. mppx leaves them unscoped. |
| Payment capability advertisement (pympp `payment_capabilities`) | ✅ (added) | `mpp.mcp.payment_capabilities(mpp)` for `capabilities.experimental`. mppx has no helper. |
| Tool gating helper (pympp `@pay`) | ✅ (added) | `@paid(handler)` for `MCPServer` tools. mppx documents `throw result.challenge` instead, which also works. |
| `McpClient.wrap(client)` (monkeypatches `callTool`) | ⚠️ | `McpClient(session, methods=...)` wrapper. `call_tool` returns `PaidCallToolResult` with `.receipt`. |
| Payment handling for -32042/-32043 and `_meta` payment-required results, preferences, approval hook, 3 attempts | ✅ | |
| `McpClient.integration.test.ts` (localnet) | ❌ | Covered over an in-process `MCPServer`. |

## Key differences from mppx

1. **Language idioms, same wire.** snake_case keyword arguments, frozen dataclasses for values,
   pydantic for method schemas and `async def` everywhere. Header formats, JSON keys, problem
   types, HMAC ids and persisted store records are identical, and stores can be shared with mppx
   servers.
2. **HTTP stack.** The client is built on `httpx` (`fetch`, `client()`, `payment_transport`), and
   global fetch is never patched (`polyfill`/`restore` don't exist). The server uses
   framework-neutral `Request`/`Response` types with a Starlette/FastAPI adapter instead of
   Express/Hono/Next/Elysia middleware.
3. **Methods are three objects.** `Method` (schemas), `ClientMethod` and `ServerMethod` (hooks).
   `ServerMethod` takes either `verify` or `validate` + `broadcast`.
4. **RPC clients carry no chain.** The Tempo `RpcClient` learns its chain via `eth_chainId` once.
   Checks that mppx performs at construction from a viem chain happen on first use. Accounts are
   local secp256k1 `TempoAccount`s, optionally signing as an access key.
5. **Cancellation replaces `AbortSignal`.** Cancelling after a credential was sent raises or emits
   `PaymentOutcomeUnknownError`.
6. **pympp 0.15 hardening kept.** Where pympp 0.15 is stricter than mppx (split-leg binding,
   sponsored-submission recovery, EVM settlement claims), this release keeps pympp's behaviour.
   The parity tables mark each case.
7. **MCP challenges are bound to the tool.** mppx leaves them unscoped, so a credential paid
   for one tool pays for any tool with the same terms. pympp binds each challenge issued through
   `mcp_sdk()` to `tool:<name>` of the called tool; an explicit `scope=` wins.
8. **No compatibility shims.** Deprecated mppx aliases (`evm({currency})`, client `assets`,
   `feePayerPolicy.maxInFlight*`) are not provided.

## Verification

### Tests

`uv run pytest --co -q -p no:cacheprovider tests/<area> | tail -1` on 2026-10-25:

| Area | Tests |
|---|---|
| `core` | 352 |
| `server` | 183 |
| `client` | 104 |
| `tempo` (`foundations` 360, `charge` 453) | 813 |
| `stripe` | 147 |
| `evm` | 88 |
| `x402` | 123 |
| `mcp_sdk` | 55 |
| `conformance` (pytest wrappers of the runners) | 3 |
| **Total** | **1868** |

`uv run pytest -q -m "not conformance"` reported **1865 passed, 3 deselected**. `uv run pyright`
reported 0 errors, and ruff passes.

The default run never touches a live network. Chain behaviour runs against in-memory JSON-RPC
nodes served through `httpx.MockTransport`. anvil cannot execute Tempo `0x76` transactions or
TIP-20 precompiles, so mppx's localnet suites were ported against these fakes. Byte-level
fixtures generated by mppx/ox/viem pin transactions, signatures and typed data.

### Conformance

`make conformance` on the vendored `tempoxyz/mpp-tools` `6eb9b98` with the `python` adapter, re-run
on 2026-10-25:

| Suite | Result |
|---|---|
| Vectors (`vector_runner.py`) | **153 / 153 passed** (0 version-skipped, 0 capability-skipped) |
| Server verification (`server_verify_runner.py`) | **9 / 9 passed** |
| Flows (`flow_runner.py`, TS compliance server mppx 0.13.5) | **34 / 34 passed** (no capability skips) |

The flow runner's compliance server is pinned to mppx 0.13.5 in `conformance/package.json`
(upstream pins 0.11.0); it runs unchanged on that version.

Scenarios that the vectors restrict to other adapters were also run by hand against the python
adapter on the previous vendor (`0d53b375`), and they pass. `6eb9b98` does not change them.
Details: [parity/conformance.md](parity/conformance.md).

**Disclosure: adapter-level shims.** The vectors, flows and the SDK are unchanged. Three fixture
assumptions differ from mppx, and the adapter (`vendor/mpp-tools/conformance/adapters/python/`)
bridges them. The other adapters are vendored as their upstream manifests only, never built.

1. **Re-signing short-secret server-verification cases.** The cases use a 10-byte secret, which
   pympp (like mppx) rejects; the golden TS adapter does not implement `server.verify` at all.
   For keys shorter than 32 bytes, the adapter first checks the HMAC with the case key using the
   public `Challenge.verify` (a failure is reported as `invalid_challenge`). It then re-issues the
   echoed challenge id under a 41-byte adapter key and runs the unchanged SDK route handler.
   Binding, expiry, verification and problem details all come from pympp.
2. **Filling the missing receipt `from`.** The `tempo-receipt-verification` fixtures omit the
   receipt `from` field, which real nodes always return and which mppx/pympp bind as the payer.
   The adapter fills it with the debited account of the first transfer log.
3. **Prefixing fee-payer cosign error phrases.** `tempo-fee-payer-cosign.json` was written for
   mpp-rb/mpp-rs. It expects sponsor-policy checks before payment binding, and different
   messages. The adapter runs the SDK's own building blocks in sponsor order and reports
   `<vector phrase>: <unchanged SDK message>` through a fixed 6-entry table. Without the table,
   6 scenarios would fail on `messageContains` only; the error type is `verification_error`
   either way.

## Planned feature PRs

These features were removed from this release and come back as separate pull requests:

- **CLI and validation:** the `mpp` command-line client and the server validation library behind
  `mpp validate`.
- **Proxy:** the payment-gated reverse proxy with service presets.
- **Discovery:** OpenAPI payment discovery documents.
- **Attestation:** RFC 9421 HTTP message signatures, TAP and Web Bot Auth, and the
  `attestation=` options.
- **x402 FastAPI middleware:** `mpp.x402.fastapi` on the official x402 package.
- **x402 MCP wrapper:** `mpp.x402.mcp` and the x402 negotiator.
- **ASGI middleware:** `mpp.server.asgi` (`PaymentMiddleware`, `gate`, `to_app`).
- **Offer selection:** `Mpp(select_offers=...)`.
- **Tempo auto-swap:** client payment through the stablecoin DEX.
- **Tempo machine-token routes:** MACH charge routes and settlement senders.
- **Tempo sponsor budget:** shared in-flight sponsor budget (`SponsorBudgetConfig`).
- **Tempo smart-wallet proofs:** ERC-1271/ERC-6492 and P256/WebAuthn verification of
  zero-amount proofs.
- **Tempo JSON-RPC wallets:** `JsonRpcAccount` and the EIP-5792 `wallet_sendCalls` push path.
- **Tempo key-authorization manager:** pending key authorizations on access-key accounts.
- **Tempo signers:** P256, headless WebAuthn and native multisig signing accounts.
- **Stripe Connect:** Connect settlement (`ConnectSettlement`, `TransferData`, `connect=`).
- **Stripe hosted fee payer:** Stripe-hosted Tempo fee sponsorship.
- **Stripe Base rail:** the Base (EVM) charge rail in `stripe.create()` machine payments.

## Known gaps

None of these affect wire compatibility.

- **Not runnable in CI:** mppx's live Stripe, Coinbase facilitator and Tempo/anvil localnet
  integration suites, which need live credentials or chains. Equivalent flows run against fakes.
- **`mpp.store.memory()` never evicts** (same as mppx). Use Redis or another shared store in
  production.
- **trio is not supported.** The SDK runs on asyncio.
- **Upstream mpp-tools runner issues** (not SDK bugs): `flow_runner.py` leaves the tsx compliance
  server running, which `make conformance-flows` works around by reaping it, and it uses a fixed
  port, so concurrent runs on one machine collide. `sdk_version.py` resolves the python version
  from the `pympp` distribution, so a future `python` `sdkVersions` constraint would fail until
  upstream learns about `pympp`.
