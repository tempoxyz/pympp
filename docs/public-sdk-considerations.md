# Public SDK considerations

Policies and operational notes for maintaining and running pympp as a public SDK.

- [Public API surface](#public-api-surface)
- [Versioning](#versioning)
- [Conformance gating](#conformance-gating)
- [Typing](#typing)
- [Supported Python versions](#supported-python-versions)
- [Optional dependencies](#optional-dependencies)
- [Security considerations for operators](#security-considerations-for-operators)
- [Concurrency and async](#concurrency-and-async)
- [Logging and warnings](#logging-and-warnings)
- [Error model](#error-model)
- [Release checklist](#release-checklist)

## Public API surface

- **Public** means a name listed in `__all__` of a module whose dotted path has no component
  starting with `_`. Examples: `mpp.Challenge`, `mpp.server.Mpp`, `mpp.tempo.server.charge`,
  `mpp.store.memory`.
- Every public module declares `__all__`; names outside it are not part of the API even when
  they lack a leading underscore.
- **Private**: any module or package whose name starts with `_` (`mpp._json`,
  `mpp.tempo._internal`, `mpp.server._mpp`, `mpp.tempo.client._charge`, …). Private code may
  change or move in any release. Import only from the public package. For example, use
  `from mpp.server import Mpp`, not `from mpp.server._mpp import Mpp`.
- **Wire formats** (header syntax, JSON keys, problem `type` URIs, persisted store records) are
  governed by the spec and mppx, not by this package's version. They change only when the
  protocol changes.
- **Extension points** that third parties implement are part of the public API and follow
  the same compatibility rules: `ClientMethod`/`ServerMethod` hooks and their context
  dataclasses, `mpp.server.Transport`, `mpp.client.Protocol`/`ClientTransport`,
  `mpp.store.Store`/`AtomicStore`, `mpp.stripe.StripeClient`/`StripeRawClient` and
  `mpp.evm.TypedDataSigner`.
- Hook context dataclasses may gain new fields with defaults in minor releases. Don't construct
  them positionally (they are `kw_only`).

## Versioning

- The package follows [Semantic Versioning](https://semver.org/). Until 1.0, a **minor** bump
  (`0.x → 0.(x+1)`) may break the public API and a **patch** bump must not. From 1.0, breaking
  changes need a major bump. Breaking changes are listed in the release notes with migration
  instructions.
- The current version is `0.1.0` (`pyproject.toml`), exposed as `mpp.__version__`. Stripe analytics metadata reports
  `mpp_sdk=pympp/<version>`.
- The package version is independent of mppx and the spec. Each release records what it was
  verified against:

  | Reference | Pinned at |
  |---|---|
  | mppx (behaviour reference) | `wevm/mppx` `13a90352` (package version 0.13.5). |
  | Conformance suite | `tempoxyz/mpp-tools` `6eb9b98` (`vendor/mpp-tools/UPSTREAM_SHA`). The flow runner's compliance server is mppx 0.13.5, pinned in `conformance/package.json`. |
  | Spec | `tempoxyz/mpp-specs` drafts: core `draft-httpauth-payment-00`, intent charge, methods (tempo, stripe, evm), extension MCP transport. mppx behaviour wins where a draft is ambiguous or says nothing. |

- When mppx changes observable behaviour, port the change, add or adjust tests, and bump at
  least the minor version if the change affects users (new defaults, stricter validation).

## Conformance gating

- `vendor/mpp-tools` is a vendored copy of the conformance assets: golden vectors, flows and
  server-verification cases. They are unmodified; only the compliance server's mppx pin differs
  from upstream (0.13.5 instead of 0.11.0). The Python adapter is in
  `vendor/mpp-tools/conformance/adapters/python/`.
- Run everything with `make conformance`, which installs dependencies and then runs vectors,
  server verification and flows. Each suite also has its own target:
  `make conformance-vectors`, `make conformance-server-verify` and `make conformance-flows`
  (flows need Node ≥ 22.18). `uv run pytest -m conformance` runs the same runners from pytest and
  skips them when uv or the node dependencies are missing.
- In CI, `.github/workflows/ci.yml` runs three jobs: `lint` (ruff + pyright), `test` (pytest on
  3.12/3.13/3.14, excluding the conformance marker) and `conformance` (all three runners). A
  release requires all three to be green.
- The adapter contains a few documented shims for vectors whose assumptions differ from mppx.
  They are listed in [coverage.md](coverage.md#conformance). Re-check them whenever
  `vendor/mpp-tools` is re-vendored. Keep the other adapters' upstream manifests
  (`adapters/{go,java,ruby,rust,typescript}/adapter.json`), and regenerate the adapter's `uv.lock` when root dependencies change.

## Typing

- The package ships `src/mpp/py.typed` (PEP 561), so type checkers use the inline annotations.
- All public functions are annotated. `uv run pyright` (standard mode, `include = ["src"]`) runs
  in CI. Generic APIs use PEP 695 syntax (`Credential[P]`, `VerifyContext[PayloadT]`,
  `Transport[Input, ChallengeOut, ReceiptIn, ReceiptOut]`).
- Optional dependencies are typed against their own stubs or inline types. Install the extras
  (`uv sync --all-extras`) before type-checking.

## Supported Python versions

- Supported versions are CPython **3.12, 3.13 and 3.14**: `requires-python = ">=3.12"`, the
  classifiers and the CI matrix agree. The code uses 3.12 features (PEP 695 generics, `type`
  aliases), so 3.11 cannot be supported without a rewrite.
- Support for a CPython version ends with its end of life or with the next minor release after
  that, whichever comes later. Adding a new CPython version only needs the CI matrix and the
  classifiers updated.

## Optional dependencies

- Base install: `httpx` + `pydantic`. Anything heavier lives in an extra (see the
  [README](../README.md#install)).
- Subpackages import their extra at **module import time**: `mpp.tempo` needs `pytempo`/`rlp`/
  `eth-account`, `mpp.server.starlette` needs `starlette`, and `mpp.mcp_sdk` needs `mcp`. Core
  packages never import them. Cross-package hooks (the x402 protocol in the default client
  protocols, the Tempo rail inside Stripe machine payments) import lazily, only when used.
- A missing extra raises `ModuleNotFoundError` with the install command, for example
  `'rlp' is required for this feature. Install it with: pip install "pympp[tempo]"`.
- Use lower bounds only (`>=`) and no transitive pins, so applications can resolve their own
  dependency trees. Raise a lower bound only when code needs a newer API, and keep `uv.lock` for
  development only.
- New optional integrations go behind a new extra and must not add imports to `mpp`,
  `mpp.server` or `mpp.client`.

## Security considerations for operators

### Secret key

- `Mpp` requires `secret_key` (or `MPP_SECRET_KEY`) of **at least 32 bytes**. Generate it with
  `openssl rand -base64 32`. The key authenticates challenge ids (HMAC-SHA256), which is what
  makes verification stateless.
- **Rotation.** Only one key is accepted at a time. When you rotate, credentials for challenges
  issued under the old key fail with `invalid-challenge`, and the client receives a fresh 402.
  Challenges expire after 5 minutes by default, so a rolling deploy causes at most a few
  minutes of re-challenges. Nothing is charged twice, because a rejected credential is never
  settled.
- Every replica behind a load balancer needs the same key.

### Realm

- Set `MPP_REALM` (or `realm=`) in production. Without it, the realm comes from the request's
  `Host` header, which the client controls and which reverse proxies may rewrite. The HMAC
  still binds challenge and credential to that value, but an explicit realm keeps challenges
  stable across hosts and proxies.

### Replay protection and stores

- One-time payments (Tempo charge hashes and transactions, EVM authorizations) rely on an
  `AtomicStore`. The default `mpp.store.memory()` is **per
  process**. With several workers, replicas, or a `Mpp` created per request, a credential
  accepted by one instance can be accepted again by another. Tempo and EVM emit a `UserWarning`
  when they fall back to memory. Use a shared store, for example `mpp.store.redis(redis.asyncio.Redis(...))`.
- The memory store never evicts. Expired replay markers stay until the key is reused, so a
  long-running process grows with traffic (mppx behaves the same). Redis claims expire on their
  own.
- Tempo zero-amount proof credentials are replay-protected only when you pass a `store`.
- Tempo replay claims and recovery records use mppx's keys and JSON layout, so Python and
  TypeScript servers can share one store. Keep key prefixes consistent across both. pympp 0.15
  used different keys (see the [migration guide](migration-from-pympp.md#dropped-from-015)).

### Route and tool binding

- `@paid` binds challenges to `"METHOD /route/template"` unless you configure `scope=`.
  Behind a reverse proxy, make sure the path the app sees is the path the client requested.
- **MCP SDK tools are bound per tool.** `mcp_sdk()` binds each challenge to `tool:<name>` of
  the called tool, so a credential for one tool cannot pay for another tool with identical terms
  (mppx leaves them unscoped). An explicit `scope=` wins, so tools sharing a scope accept each
  other's credentials.
- Body digests (`digest=`) bind challenges to request bodies.

### Client side

- **Redirects and paid retries.** `fetch()` / `mpp.client()` follow redirects only before
  payment. A redirect answering a paid request is returned unfollowed, so the credential is
  never forwarded to another origin. Paid retries are never repeated: if the outcome is unknown
  (cancellation, transport error after sending), the client raises or emits
  `PaymentOutcomeUnknownError` with the credential and, when known, the transaction hash.
  Reconcile instead of retrying blindly.
- **Restrict where you pay.** Pass `Mpp(allowed_origins=["https://api.example.com"])` when
  URLs come from untrusted sources. A 402 from any other origin, checked on the URL that
  returned it, is returned unchanged without a credential. Also set method policies: Tempo `expected_recipients`, `max_amount`/`max_atomic_amount` with
  `currencies`, `allowed_chain_ids`; EVM `networks`, `currencies`, `max_amount`. The realm is
  not an authenticated origin.
- **Timeouts.** `fetch()` sets no timeout by default. Pass `timeout=` when calling untrusted
  servers.

### Tempo fee sponsorship

- With `fee_payer=` set, the server co-signs and pays gas for client transactions. Sponsored
  transactions must pass the sponsor policy: per-chain limits on gas, fee per gas and total fee,
  a maximum validity window, an expiring nonce, no access list, exact payment calls and an
  allowed fee token. Tighten the policy with `fee_payer_policy=` and `allowed_fee_tokens=`.
- Remote fee payers (`fee_payer="https://…"` / `RemoteFeePayer`) receive the client transaction
  for signing, and the signed result is a spending capability the caller can broadcast
  elsewhere. Only point them at services that authorize, validate, simulate and enforce their
  own spending limits before signing.

### RPC

- The Tempo `RpcClient` retries transient failures like viem: 3 retries, exponential backoff
  from 150 ms or `Retry-After`, on HTTP 403/408/413/429/5xx, network errors and JSON-RPC
  -1/-32005/-32603/429/-32007. Broadcasts (`eth_sendRawTransaction*`) are **never** retried.
  An ambiguous broadcast failure is resolved by polling for the receipt within
  `confirmation_timeout_ms`.
- The default endpoints are Tempo's public RPCs (`mpp.tempo.chains.RPC_URLS`). Production
  servers should use a dedicated endpoint via `get_client=`.

## Concurrency and async

- Every I/O API is `async def` and runs on **asyncio**. The code uses asyncio primitives such
  as `asyncio.Lock`, `asyncio.shield` and task cancellation, so trio is not supported. The MCP
  integration runs on the MCP SDK's anyio, which is fine under asyncio. There is no synchronous
  client.
- Hooks (`verify`, `can_offer`, event handlers, key resolvers, …) may be plain functions or
  coroutines. Blocking work in a sync hook blocks the event loop, so offload it with
  `asyncio.to_thread`.
- `Mpp` instances (server and client) are safe to share across concurrent requests on one
  event loop. Create them once at startup, not per request. A per-request instance also loses
  in-memory replay state.
- Cancellation is the abort mechanism (mppx `AbortSignal`). Cancelling a client request after
  its credential was sent produces `PaymentOutcomeUnknownError`.

## Logging and warnings

- Libraries log through `logging` and never configure handlers. The logger names are
  `mpp.server` (engine and event-handler errors), `mpp.client` (client event-handler errors,
  at debug level), `mpp.tempo` (Tempo server diagnostics) and
  `mpp.stripe` (payment recording, deposit addresses).
- When a hook raises an error that is not a `PaymentError`, the client gets a generic 500
  problem and the cause is logged on `mpp.server` with its traceback. Monitor that logger.
- `warnings.warn(UserWarning)` reports configuration risks once per method name, such as the
  in-memory fallback store. Filter or escalate them with the standard `warnings` machinery,
  for example `-W error::UserWarning` in tests.

## Error model

- All payment errors subclass `mpp.errors.PaymentError` and render as RFC 9457 problem details
  with the same `type`, `title` and `status` as mppx: `to_problem_details(challenge_id=None)` →
  `{"type", "title", "status", "detail", ["details"], ["hint"], ["challengeId"]}`.
  `type` URIs are `https://paymentauth.org/problems/<slug>`.

  | Class | Slug | Status |
  |---|---|---|
  | `PaymentRequiredError` | `payment-required` | 402 |
  | `MalformedCredentialError` | `malformed-credential` | 402 |
  | `InvalidChallengeError` | `invalid-challenge` | 402 |
  | `VerificationFailedError` | `verification-failed` | 402 |
  | `CredentialReplayedError` | `verification-failed` | **403**, no new challenge |
  | `PaymentExpiredError` | `payment-expired` | 402 |
  | `InvalidPayloadError` | `invalid-payload` | 402 |
  | `PaymentInsufficientError` | `payment-insufficient` | 402 |
  | `PaymentActionRequiredError` | `payment-action-required` | 402 |
  | `PaymentOutcomeUnknownError` | `payment-outcome-unknown` | 402 (client-side) |
  | `BadRequestError` | `bad-request` | 400 |
  | `PaymentMethodUnsupportedError` | `method-unsupported` | 400 |
  | `InternalPaymentError` | `internal-payment-error` | 500 (generic message; cause not exposed) |

- Constructors are keyword-only. `details` holds safe diagnostic context that is serialized
  into the problem. `cause` (`__cause__`) is never serialized.
- A 402 answer carries a fresh challenge plus the problem body. A 403 replay carries no
  challenge, so auto-paying clients do not pay again.
- Over MCP, problems map to JSON-RPC errors: -32042 payment required, -32043 verification
  failed, -32602 malformed, -32603 internal. Use `mpp.mcp.error_code(error)` for the mapping.
- Parsing errors for headers (`Challenge.deserialize`, `Credential.deserialize`, …) are
  `ValueError` subclasses, not `PaymentError`s.
- Client policy violations (wrong chain, amount cap, no compatible method) raise `ValueError`
  before any credential is created.

## Release checklist

1. `main` is green in CI: lint, pyright, tests on 3.12–3.14, conformance.
2. Locally: `make check` and `make conformance`. Record the pass counts (vectors, flows,
   server verification) in the release notes.
3. If the mppx reference moved, port the behaviour changes, update the parity tables in
   [docs/parity/](parity/) and update the pins
   in [Versioning](#versioning).
4. If `vendor/mpp-tools` was re-vendored, re-check the adapter shims (see
   [coverage.md](coverage.md#conformance)) and keep the restored adapter manifests.
5. Update `version` in `pyproject.toml` (semver; minor bump for breaking changes before 1.0),
   then the changelog and release notes. Breaking changes need migration notes.
6. Check the public surface: no new public names without docs, `__all__` lists match, and
   nothing public imports from a private module in its signature.
7. Build and inspect: `uv build`. The wheel contains `mpp/py.typed`. Smoke-test
   in a clean venv: `pip install dist/*.whl` (base only), then `python -c "import mpp,
   mpp.server, mpp.client"`, then the same with `[tempo]`.
8. Publish to PyPI with trusted publishing. Tag `vX.Y.Z` and create the GitHub release.
