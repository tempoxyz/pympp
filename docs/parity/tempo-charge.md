# Tempo charge parity (`mpp.tempo.server` / `mpp.tempo.client` charge)

Owner: tempo-charge. Reference: mppx `src/tempo/server/{Charge,Relay,Methods}.ts`,
`src/tempo/server/internal/{fallback-store,request-body}.ts`,
`src/tempo/client/{Charge,ResolveAccount,Methods}.ts`, viem `sendCallsSync` / `tempo/Account.ts`,
ox `tempo/{SignatureEnvelope,MultisigConfig}.ts`. Tests: `tests/tempo/charge/` (453 tests,
all against a mocked JSON-RPC node, `tests/tempo/charge/_charge_node.py`, served through
`httpx.MockTransport`; no anvil: anvil cannot execute Tempo `0x76` transactions or TIP-20
precompiles, and mppx's integration suite runs against a Tempo dev node).

Public surface:

* Server: `mpp.tempo.server.charge(**kw) -> list[ServerMethod]` (mppx `tempo.charge`: ordered
  currency offers), `tempo(**kw)` / `common` (the charge offers),
  `RelayOptions`, `FeePayerPolicy` (= foundations `PolicyOverrides`),
  `RemoteFeePayer`, `ValidateSender` / `ValidateSenderParams`, `ValidationDetails`. The single-currency
  method factory is `mpp.tempo.server._charge.charge` (mppx `Charge.charge`, not public in mppx
  either).
* Client: `mpp.tempo.client.charge(**kw) -> ClientMethod`, `tempo(**kw)` / `common`,
  `ChargeContext`, `transaction_hash`,
  resolve-account types (`ResolveAccountInfo`, `ExecuteCalls`, `SignPaymentProof`,
  `AuthorizePaymentChannel`, `ResolveAccount`),
  accounts (`secp256k1_account`).

| mppx feature | Status | Notes |
|---|---|---|
| Default currency per chain (`Charge.charge`: USDC.e mainnet, pathUSD Moderato/unknown), `decimals` default 6 | Implemented | `test_charge_server_config.py::TestDefaultCurrency`. |
| Ordered offers (`tempo.charge` / `tempo()`): OUSD then USDC.e mainnet, OUSD then pathUSD testnet; `currencies` (addresses or `Token` definitions filtered by chain + USD, deduped by address, per-token decimals); deprecated `currency`; conflicting/empty lists rejected | Implemented | `_methods.charge` / `_methods.tempo`, currency resolution from foundations `currencies.resolve`. The deprecated single-`currency` `tempo()` path skips resolution exactly like mppx. |
| `tempo()` group | Intentionally different | `tempo()` returns only the `charge` offers; unknown kwargs raise `TypeError` (TS ignores extra keys). |
| Request hook: chain resolution (request → `chain_id` → testnet → client chain), `No client configured with chainId X.`, `feePayer` resolution (challenge: `true`; credential: the account / `true` for hosted; explicit `false` kept) | Implemented | camelCase or snake_case route options accepted (normalized to field names). |
| `Client not configured with chainId X.` (viem client with a fixed chain) | Intentionally different | An `RpcClient` has no static chain; checking would cost an `eth_chainId` per request. When no chain is configured the default client's chain is read once via `eth_chainId` (cached). |
| Hash (push) credentials: receipt + transfer-log matching (memo-first, `Transfer`/`TransferWithMemo` collapse, splits in any order), credential `source` binding, `validateSender`, payer = debited account, replay claim (case-insensitive), `getTransactionByHash` funding attribution only at broadcast | Implemented | Verification core from foundations `charge.verify_hash_credential`. `validate_sender` receives `ValidateSenderParams(sender, expected_sender, source)`. |
| Transaction (pull) credentials: `0x76`/`0x78` only, signed sender required, source/sender binding, exact call matching (sponsored) or recognized routes, challenge-bound memo, simulation (`eth_call`) before broadcast, canonical re-serialization (raw recovery ids), pre-/post-broadcast replay claims, claim release on failure | Implemented | |
| Proof (zero-amount) credentials: EIP-712 `MPP` v3 bound to the account, source DID/chain checks, keychain access-key proofs with active-key check, replay protection only with an explicit store, receipt reference = challenge id | Implemented | |
| Local fee sponsorship: fee-token selection (`feeToken` / funded allowed token, pathUSD first), `allowedFeeTokens` (non-empty, default per chain), two-phase preflight simulation, sponsor policy, co-signing | Implemented | Uses foundations `fee_payer` helpers. |
| Remote fee payer (URL string or `RemoteFeePayer(url, headers, http)`): `eth_fillTransaction` with `feePayer: true` sent only to the fee payer, fee-token allowlist, signature recovery; `feeToken` + remote rejected | Implemented | Dedicated `RpcClient` for the fee payer (mppx wraps the viem transport with `withFeePayer`; broadcasts of the co-signed transaction go to the node either way). |
| Confirmation/recovery: sync broadcast with 2/3 of `confirmation_timeout_ms`, ambiguous-error classification (timeouts, lost connections / 5xx, JSON-RPC 4, "already known"), receipt polling capped by `validBefore + 2s` plus one final lookup, definitive errors fail fast, retries re-broadcast | Implemented | `test_charge_recovery.py` ports every case of `Charge.recovery.test.ts`. Python error mapping: `RpcTransportError(status None / >=500)`, `TimeoutError`, `httpx` timeout/network errors. Beyond mppx (pympp#318/#323): a locally sponsored submission whose outcome stays unknown keeps a recovery record (the exact co-signed envelope, written atomically before the send, failing closed). A retry reconciles it from its receipt, re-sends only that envelope while 15 s of validity remain, answers `InternalPaymentError` (not payable) while the outcome is unknown, and clears the record once chain time passes `validBefore` with no receipt. Not ported: reconciliation after the challenge itself expired, since the engine rejects expired credentials first. |
| `waitForConfirmation: false` (optimistic broadcast, sponsored exposure kept `pending` until reconciliation) | Implemented | |
| Splits + memo/attribution binding matrix (bound/plain/other client/uppercase/custom vs other challenge/realm) for hash, transaction, optimistic and sponsored | Implemented | 60-case port in `test_charge_server_config.py`. pympp 0.15 hardening (pympp#313), beyond mppx: matching prefers legs bound to this challenge, a neutral split leg in a receipt or transaction that also pays another challenge is rejected, and the client binds every split leg without a fixed memo to the challenge. |
| Relay (`/v1/mpp/validate` + `/v1/mpp/broadcast`, base path preservation, safe error codes, `expired` → payment-expired, opaque failures, no idempotency key) | Implemented | `RelayOptions(api_key, api_base_url, http)`. mppx's adapter keeps the legacy `verify` alongside `validate`/`broadcast`; the Python `ServerMethod` forbids that combination, so the adapter replaces `validate`/`broadcast` and `ServerMethod.settle` is the combined path. |
| `fallbackStore` warn-once | Implemented | `warnings.warn` once per method name. |
| Client: policy (`expectedChainId`, `allowedChainIds`, `expectedRecipients`, `currencies`, `maxAmount`/`maxAtomicAmount` exact parsing), checked during selection (`can_handle_challenge`) and before signing | Implemented | |
| Client: chain resolution (challenge → pin → single allowed chain → client chain) and resolved-client chain mismatch | Implemented | The client's chain is read once via `eth_chainId` (cached per `RpcClient`). |
| Client: attribution memo (`clientId` fingerprint), splits, zero-amount proofs (root payer for access keys), `resolveAccount` operations, push/pull modes, `validBefore` capping, gas `+5000` before fee-payer mode, sponsored `0x78` without fee token, in-flight signing sharing, `transactionHash` for `PaymentOutcomeUnknownError` | Implemented | Transactions are filled with `eth_fillTransaction` (viem behavior; 1.2x base-fee multiplier), falling back to `eth_estimateGas` + fee estimation when the node lacks it. |
| Native multisig (TIP-1061) signature envelopes (`0x05`) | Implemented | `mpp.tempo._internal.signature`: `MultisigSignature` serialize/deserialize/RPC with ox config validation (`tests/tempo/foundations/fixtures/ox_vectors_3.json`). viem `Account.fromMultisig` signing is not ported. |
| Type-level tests (`*.test-d.ts`) | Not applicable | |
| RPC retries (viem `http` transport: 3 retries, 150ms·2^n backoff or `Retry-After`, HTTP 403/408/413/429/5xx, network errors, JSON-RPC -1/-32005/-32603/429/-32007; broadcasts never retried; non-2xx = HTTP error) | Implemented | `RpcClient(retry_count=3, retry_delay=0.15)`, `rpc.should_retry`. |
| Strict ASCII full-match validation (addresses, hex, did:pkh, amounts, timestamps) | Implemented | `re.fullmatch` + `[0-9]` across `mpp.tempo`; `to_bytes` rejects whitespace. |
| Client `canHandleChallenge` returns false for any error | Implemented | Malformed offers are skipped. |
