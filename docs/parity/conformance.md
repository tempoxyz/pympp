# Conformance (mpp-tools) parity

Owner: conformance. pympp runs the vendored `tempoxyz/mpp-tools` conformance suite
(`vendor/mpp-tools`, `UPSTREAM_SHA` 6eb9b98) **unchanged**, through the official runners, with
the `python` adapter at `vendor/mpp-tools/conformance/adapters/python/`. The flow runner's TS
compliance server runs on **mppx 0.13.5** (`conformance/package.json` pins it exactly; upstream
6eb9b98 pins 0.11.0).

## Results (python adapter)

| Suite | Runner | Result |
|---|---|---|
| Vectors (`vectors/*.json`) | `scripts/vector_runner.py --adapter python` | **153 / 153 passed**, 0 failed, 0 version-skipped, 0 capability-skipped |
| Flows (`flows/flows.json` vs `golden-results.json`, TS compliance server, mppx 0.13.5) | `scripts/flow_runner.py --adapter python` | **34 / 34 passed** (no capability skips; `http.payment_request` is declared) |
| Server verification (`server-verification/cases.json`) | `scripts/server_verify_runner.py --adapter python` | **9 / 9 passed** |

Scenarios the vectors restrict to other adapters via `adapters` (not counted by the runner, not
version skips) were run by hand against the python adapter on the previous vendor (`0d53b375`) and
passed; this was not repeated for 6eb9b98, whose changes do not touch them:
`www-authenticate::payment_authorization_header` (rust), `www-authenticate::extended_method_identifier`
(typescript, rust), `authorization::credential_with_payment_authorization_header` (rust), and all
five `stripe-external-id-binding` scenarios (typescript, ruby).

`sdkVersions` constraints: only `{"rust": ">0.12.0"}` exists (2 scenarios, both also
`adapters: ["rust"]`). No scenario carries a `python` constraint, so nothing is version-skipped
or misapplied for python. Caveat: `scripts/sdk_version.py` resolves the python version from the
`pympp` distribution; if a `python` constraint is ever added it will fail loudly (not skip) until
upstream learns about `pympp` (version 0.1.0).

## How to run

```bash
make conformance              # install + vectors + server-verify + flows
make conformance-vectors      # each suite individually (after `make conformance-install`)
make conformance-server-verify
make conformance-flows        # needs node >= 22.18 (npm ci in the conformance dir)
uv run pytest -m conformance  # same runners as a pytest (skips without uv / node deps)
```

CI: `.github/workflows/ci.yml` job `conformance`.

## Adapter

* `pyproject.toml` depends on the repo itself: `pympp[tempo]` with
  `pympp = { path = "../../../../..", editable = true }`; `uv.lock` regenerated. Regenerate it
  (`cd vendor/mpp-tools/conformance/adapters/python && uv lock`) whenever the root
  dependencies change — the manifest `build` step is `uv sync --locked`.
* `adapter.json` keeps the name `python`; capabilities: every operation in `operations.json`
  (`challenge.*`, `credential.*`, `receipt.*`, `base64url.*`, `challenge.id`,
  `http.payment_request`, `stripe.external_id_binding`, `tempo.proof.typed_data`,
  `tempo.receipt.verify`, `tempo.fee_payer.cosign`, `server.verify`). `command` uses
  `uv run --no-sync` (the runner's `build` step syncs) to keep start-up inside the 1 s budget
  of the bounded-duration vectors; SDK modules are imported lazily per operation.
* JSON ABI only (the legacy per-command CLI of the old pympp adapter is gone).

| Operation | pympp API used | Notes |
|---|---|---|
| `challenge.parse/format` | `mpp.Challenge.deserialize` / `from_dict().serialize()` | `meta` (decoded `opaque`) is SDK-only and dropped from the canonical object. |
| `credential.parse/format` | `mpp.Credential.deserialize` / `.serialize()` | |
| `receipt.parse/format` | `mpp.Receipt.deserialize` / `from_dict().serialize()` | non-base receipt fields are reported under `extra`. |
| `base64url.encode/decode` | adapter-level (stdlib) | Same as `golden/adapter.ts`: strict URL-safe alphabet, fatal UTF-8. pympp's internal decoder is intentionally lenient like mppx/ox. |
| `challenge.id` | `mpp.challenge.compute_id` | Adapter-level `secretKey >= 32 bytes` check, exactly like `golden/adapter.ts` (`error_weak_secret_key`). |
| `tempo.proof.typed_data` | `mpp.tempo._internal.proof.legacy_v2_typed_data` | The vector pins the pre-binding v2 shape that `golden/adapter.ts` hardcodes; the current contract (v3, with `account`) is `mpp.tempo.proof.typed_data`. |
| `tempo.receipt.verify` | `mpp.tempo.server.charge(get_client=...)` + `mpp.broadcast_credential` | In-memory JSON-RPC fixture via `httpx.MockTransport` (see fixture note below). |
| `tempo.fee_payer.cosign` | `mpp.tempo._internal.fee_payer` (`prepare_sponsored_transaction`, `validate_calls`, `sign_as_fee_payer`), `mpp.tempo._internal.charge` (`assert_transfer_calls`, `assert_challenge_bound_call_memo`), `secp256k1_account().sign_transaction` | See "fee-payer vector" below. |
| `stripe.external_id_binding` | `mpp.server.Mpp` + `mpp.stripe.server.charge(client=fixture)` + `Mpp.verify_credential` | Mirrors `golden/adapter.ts` 1:1. |
| `server.verify` | `mpp.server.Mpp` HTTP route handler (`mpp["<method>/<intent>"](**request, expires=...)`) with a passthrough `ServerMethod` | Error type taken from the 402 problem-details `type`. See "short secrets" below. |
| `http.payment_request` | `mpp.client.Mpp(accept_payment_policy="always").fetch` with a passthrough `ClientMethod` | Mirrors the golden client method; `plain` mode uses raw httpx. |

## Intentional adapter-level adaptations (vectors unchanged, SDK not weakened)

### Short server-verification secrets

`server-verification/cases.json` signs every challenge with `secretKey: "secret-key"` (10 bytes).
pympp's `Mpp` (like mppx's `Mppx.create`) rejects secrets under 32 bytes. The reference
`golden/adapter.ts` does **not** implement `server.verify` at all (mppx would refuse the key too);
the cases were authored against mpp-go, whose `server.VerifyOrChallenge` accepts any key.
The only golden precedent is that HMAC/secret handling for conformance lives in the adapter
(`generateConformanceChallengeId`). The python adapter therefore, only when the case key is
shorter than 32 bytes:

1. performs the HMAC provenance check with the case key using the public primitive
   `Challenge.verify(secret_key)` (the same "tier 1" check `Mpp` runs first) — a failure is
   reported as `invalid_challenge`, exactly what the SDK returns;
2. re-issues the echoed challenge id under an adapter-owned 41-byte key and runs the unchanged
   SDK route handler with that key, so route binding (realm/method/intent/request), expiry
   (`missing required expires field`, `payment-expired`), method verification and problem details
   all come from pympp.

Every case was checked to fail for the expected SDK reason (e.g. "credential realm does not
match this route's requirements", "missing required expires field").

### Tempo receipt fixture without `from`

The `tempo-receipt-verification` fixtures omit the receipt `from` field. mppx/pympp bind the
transaction sender as the expected payer (`receipt has no sender` / no matching transfer), so an
incomplete fixture cannot verify (all five scenarios would "pass" or fail for the wrong reason).
Real `eth_getTransactionReceipt` results always include `from`; the adapter completes the fixture
with the debited account (topic 1) of its first transfer log. With that, the happy path verifies
and the four negative scenarios fail with "memo is not bound to this challenge" (the intended
reason).

### Fee-payer vector (`tempo-fee-payer-cosign.json`)

The reference golden adapter does not declare this capability; the vector was authored for
mpp-rb/mpp-rs. Its `messageContains` strings and check order differ from mppx:

* order: the vector expects sponsor-policy errors (gas, fee token, nonce key, validity window,
  access list) even for envelopes whose payment call is also unbound (plain `transfer`), i.e.
  policy before payment binding. mppx's charge flow binds the payment first. The adapter runs the
  SDK's own building blocks in sponsor order: `prepare_sponsored_transaction` (policy, canonical
  calls, fee token allowlist = sponsor fee token) → `validate_calls` (sponsored call pattern bound
  to the expected transfers) → `assert_transfer_calls` + `assert_challenge_bound_call_memo` →
  `sign_as_fee_payer`.
* wording: SDK (mppx) reasons are reported as `<conformance phrase>: <unchanged SDK message>`
  using a fixed 1:1 table:

| pympp / mppx reason | vector phrase |
|---|---|
| `fee-sponsored transaction accessList is not allowed` | `access list is not allowed` |
| `fee-sponsored transaction gas exceeds sponsor policy` | `gas limit exceeds sponsor policy` |
| `fee-sponsored transaction must use an expiring nonce` | `must use expiring nonce key` |
| `fee-sponsored transaction feeToken is not allowed` | `must not include fee_token` |
| `disallowed call pattern in fee-payer transaction` | `contains unauthorized extra calls` |
| `Payment verification failed: memo is not bound to this challenge.` | `no matching payment call found` |
| `fee-sponsored transaction validity window exceeds sponsor policy` | (already matches) |

The SDK messages themselves stay mppx-exact. If the lead prefers strict message equality with
mppx over a green vector, drop the table and accept 6 message mismatches (type is still
`verification_error` everywhere).

## Suite / vendoring notes

### Re-vendor 0d53b375 → 6eb9b98, compliance server mppx 0.8.18 → 0.13.5

* Copied upstream `conformance/` at 6eb9b98 verbatim (no `node_modules`, `.venv` or caches),
  plus `SPEC.md`/`LICENSE`; `UPSTREAM_SHA` updated. Kept pympp's own `adapters/python/*`
  (upstream's only adapter changes there are pympp dependency pins: a `yarl` override and lock
  bump, irrelevant to pympp). The adapter protocol, manifest schema and operations are unchanged.
  Other adapters stay manifest-only (`adapters/{go,java,ruby,rust}/adapter.json`, now including
  rust's `http.payment_request`), and `adapters/typescript/adapter.json` now runs
  `node golden/adapter.ts` (native type stripping; hence node >= 22.18).
* Upstream suite changes picked up: `challenge-id::with_opaque` now uses a valid wire opaque
  (new expected id), new `www-authenticate::comma_in_quoted_value_not_duplicate`, schema-validated
  server-verification cases (`schemas/server-verification-cases.schema.json`), capability-skip
  reporting in the vector runner, and the flow runner comparing challenges whose `opaque` carries
  `_mppx_nonce` without their id (the nonce makes every issued id unique).
* `npm install --save-exact mppx@0.13.5` in the conformance dir (lockfile regenerated; transitive
  bumps: ox 0.14.45, eventsource-parser 4.1.1, @stripe/stripe-js 9.17.0, structured-headers 2.1.0).
  No source change was needed in `flows/compliance-server.ts` or `golden/adapter.ts`: both run
  unchanged on 0.13.5 (the golden adapter's own vector run: 146 / 146 passed, 14 capability
  skips). Upstream already gave the Stripe binding server a realm (needed by mppx >= 0.14.2).
  `tsc --noEmit` reports two pre-existing typing nits in `compliance-server.ts` (`assert` import
  attribute, `accept-payment` header type), identical on 0.11.0 and not mppx API changes.
* The short-secret and receipt-`from` shims stay: 6eb9b98 still signs every server-verification
  case with `"secret-key"` (10 bytes) and the receipt fixtures still omit `from`.
* The upstream runner unit tests (`scripts/test_*.py`, 97 tests) pass except one that reads
  upstream's `.github/workflows/sdk-conformance-policy.yml`, which is not vendored.

### Earlier notes

* The vendored copy had dropped `adapters/{go,java,ruby,rust}/adapter.json`, which the vectors
  reference by name (`adapters`, `sdkVersions`); the vector runner aborts those files with
  "unknown adapter keys". The four manifests were restored verbatim from upstream
  (manifest only, no sources; they are never built when running `--adapter python`).
* `flow_runner.py` terminates `npx` but leaves the `tsx` compliance server running. A second run
  on the same port then talks to the stale server and `concurrent_replay_rejected` fails (its
  replay set is already populated). `make conformance-flows` and the pytest reap it (process
  group kill / `pkill`); upstream should start the server in its own process group.
* `uv run ruff check .` / `ruff format --check .` at the repo root also lint the vendored runner
  scripts and Markdown; `make lint` scopes ruff to `src tests scripts`.
