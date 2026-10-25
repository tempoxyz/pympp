# EVM + x402 parity (`mpp.evm`, `mpp.x402`)

Owner: evm/x402. Reference: mppx `src/evm/**`, `src/x402/**`, `src/integrations/x402/**`,
`src/client/internal/protocols/X402.ts`; spec `specs/methods/evm/draft-evm-charge-00.md`.
Tests: `tests/evm/` (88) and `tests/x402/` (123).

## EVM (`mpp.evm`)

| mppx feature | Status | Notes |
|---|---|---|
| `Types` constants (`paymentMethod`, `chargeIntent`, `eip3009`, `credentialTypes`), `challengeHash`, `networkOf`, `toSource`, `authorizationDomain`, `authorizationTypes` | Implemented | `mpp.evm.PAYMENT_METHOD`, `challenge_hash(id=, realm=)` (vector test), `network_of`, `to_source`, `authorization_domain`, `AUTHORIZATION_TYPES`, plus `authorization_typed_data(...)` (full EIP-712 message). |
| `Methods.charge` schema (display amount → atomic via `parseUnits`, checksummed currency/recipient/permit2Address, `methodDetails` {chainId, credentialTypes default `["authorization"]`, decimals, permit2Address?, splits?}) and `AuthorizationPayload` | Implemented | `mpp.evm.charge` (`ChargeRequestInput` → wire `ChargeRequest`), `AuthorizationPayload`. Field order of the wire object matches. |
| Client `evm.charge({account, authorization, decimals, maxAmount, maxAtomicAmount, networks, currencies})` + `evm(...)` group | Implemented | `mpp.evm.client.charge(...)` / `evm(...)`. Same policy checks and error messages (chain allowlist, raw-currency-needs-networks, currency allowlist, maxAtomicAmount, maxAmount with known-asset/token decimals only), EIP-3009 domain from known asset metadata or `authorization`, `validBefore` = challenge expiry or now+300, nonce = challenge hash, `did:pkh` source. |
| Deferred signer (`context: {account}` overrides configured account; missing signer reported only at credential creation) | Implemented | `ChargeContext` model; works for native and x402 challenges (ported `DeferredSigner.test.ts`). |
| Branded x402 challenges routed to the x402 exact signer (`canHandleChallenge`) and unbranded x402-shaped requests never signed as x402 | Implemented | Brand = `Challenge.protocol == "x402"`. |
| Server `evm.charge({currency, recipient, authorization, chainId, decimals, settle, x402, canOffer, onPaymentSuccess})` incl. config resolution errors | Implemented | `mpp.evm.server.charge(...)`; identical error messages. `settle(SettleParams) -> SettleResult(reference, timestamp)`. |
| `validate` (credential types, splits, recipient, amount, challenge-hash nonce unless converted from x402, validAfter/validBefore, EIP-712 signature recovery, source check, facilitator `verify` when facilitator-backed) and `broadcast` (settle → receipt) | Implemented | Lifecycle (`validate_credential` x2 then `broadcast_credential`, facilitator re-checked at broadcast, payer on `payment.success`) ported for both protocols. |
| Combined HTTP transport (`evm-http`: native `Authorization` + x402 `PAYMENT-SIGNATURE`, `PAYMENT-REQUIRED` on challenges, `PAYMENT-RESPONSE` on receipts) | Implemented | `EvmHttpTransport`. |
| `evm({currencies})` multi-offer factory (ordering, chain/address dedupe, skip unavailable chains and non-USD token definitions, errors) | Implemented | `mpp.evm.server.evm(currencies=[...], ...)`. The deprecated `evm({currency})` form is not provided (use `charge(currency=...)`); no compatibility shims. |
| `Assets` (`define`, `fromToken`, known Base/Base Sepolia/Celo/Celo Sepolia assets, `isAsset`, `isToken`, `isRawAddress`, `resolve`, `matches`, `toNetwork`, `toChainId`) | Implemented | `mpp.x402.assets` (re-exported as `mpp.evm.assets`). Known assets are module constants (`BASE_USDC`, `BASE_SEPOLIA_USDC`, `CELO_USDC`, `CELO_USDT`, `CELO_SEPOLIA_USDC`). Branding = `isinstance(KnownAsset)`. `from_token(token, chain_id=, transfer=None, version=)` (implicit EIP-3009 with the token name when only `version` is given). |
| `viem/tokens` token definitions accepted as currencies | Intentionally different | No viem in Python: `mpp.evm.tokens.Token` mirrors `defineToken` (callable with a chain id, `addresses`, `decimals`, `currency`, `name`, ...). `USDC`, `OUSD` and `POPULAR` are provided (the definitions mppx tests use). |
| `Chains` | Implemented | `mpp.evm.chains.BASE`, `BASE_SEPOLIA`, `CELO`, `CELO_SEPOLIA`. |
| `assets` legacy alias of `currencies` (client) | Not implemented | No compatibility shims (AGENTS.md); use `currencies`. |
| Signer abstraction (viem `Account.signTypedData`) | Intentionally different | `TypedDataSigner` protocol: `address` + `sign_typed_data(typed_data) -> str` (sync or async); `eth_account` `LocalAccount` objects are accepted directly. |
| Spec credential types `permit2`, `transaction`, `hash`, splits settlement | Not implemented | mppx implements only `authorization` (its schema rejects other `credentialTypes`); parity wins over the draft spec. No JSON-RPC client is therefore needed (settlement is `settle` or the x402 facilitator). |
| Malformed authorization signatures | Intentionally different (pympp 0.15) | An unrecoverable signature (not 65 bytes, bad recovery id) is a 402 `VerificationFailedError` (`signature is invalid`) instead of mppx's internal error. The wire schema still accepts any hex signature, as mppx's does. |

## x402 (`mpp.x402`)

| mppx feature | Status | Notes |
|---|---|---|
| `Types` (v2 schemas: `ResourceInfo`, `PaymentRequirements`, `PaymentRequired`, `Extension(s)`, EIP-3009/Permit2 payloads, `PaymentPayload`, `VerifyResponse`, `SettleResponse`, `Facilitator`; constants, header names, `toPaymentRequirements`) | Implemented | Pydantic models with zod semantics (unknown keys dropped, strict types, alphabetical field order). Header names `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `X-PAYMENT`, `PAYMENT-RESPONSE`. |
| `Header` codecs (standard base64 of `JSON.stringify(schema.parse(value))`), tolerant `decodePaymentRequiredEnvelope`, `InvalidJsonHeaderError` | Implemented | Byte-compatible encoding (schema key order, compact JSON). |
| `internal/RouteBinding.nonce` (sha256 of the three JCS/base64url serializations joined by `|`) | Implemented | `mpp.x402.route_binding_nonce`. |
| `internal/ChallengeBrand` | Intentionally different | Non-wire `Challenge.protocol = "x402"` (core contract) instead of a symbol property; `is_x402_challenge()`. |
| Client protocol `X402.ts` (synthetic `x402:<index>` `evm/charge` challenges per supported accept, realm = resource host, request = accept + extensions + resource; unsupported accepts filtered; credential in `PAYMENT-SIGNATURE` purging stale headers) | Implemented | `mpp.x402.protocol()` (cheap import, no optional deps); used by the core client's default protocol list. |
| `client/Exact.ts` (`createCredential`, `canHandleChallenge`; policy checks; EIP-3009 only; route-bound nonce with salted `extensions.mppx.info.nonce`, random nonce otherwise; validAfter now-600, validBefore now+maxTimeoutSeconds) | Implemented | `mpp.x402._exact` (used by `mpp.evm.client.charge`). Permit2 signing rejected with the same message. |
| `server/EvmCharge.ts` x402 path (pending credential → route binding: `accepted` match, body digest, `routeBinding` `required`/`resource`, resource URL echo, `extensions.mppx` containment with client nonce stripping, route-bound nonce check; facilitator verify/settle; `PAYMENT-REQUIRED` with `extensions.mppx` route binding; `PAYMENT-RESPONSE`) | Implemented | `mpp.x402._evm_charge` + `X402Options(facilitator, client, max_timeout_seconds=300, route_binding="required")`. Credential markers are `Credential` subclasses (`PendingX402Credential`, `X402Credential`) instead of symbols. The `EvmCharge.test.ts` cases are ported, except the `Proxy` case (no proxy in this release). |
| `server/Facilitator.ts` (`http(url)` v2 `/verify` + `/settle` envelopes, `resolve`) | Implemented | `mpp.x402.facilitator.http(url, client=httpx.AsyncClient)`. Facilitator implementations may return models or wire dicts. |
| `Facilitator.unwrapFetch` (unwrap mppx's patched global fetch) | Not needed | Python never patches a global client; pass a plain `httpx.AsyncClient`. |
| x402 v1 (`X-PAYMENT`) payments | Same as mppx | Only recognized to reject combined MPP + x402 credentials; the server path is v2-only. |
| `CoinbaseClient.integration.test.ts`, `Exact.localnet.test.ts`, `Exact.e2e.test.ts` | Not ported | Require live facilitators / a localnet with deployed FiatToken contracts. The same flows are covered end to end against facilitator doubles (`tests/evm/test_client_fetch.py`, `tests/x402/test_x402_evm_charge.py`). |

## Equivalence-audit follow-ups

- x402 wire models require `x402Version`. Every optional field rejects an explicit `null`, as zod `z.optional` does.
- Synthesized x402 challenges need an absolute `resource.url`, otherwise no offer is produced. Like mppx's `new URL(...)`, the realm keeps IPv6 brackets.

## Settlement hardening (ported from pympp 0.15, pympp#320)

mppx leaves these to custom settlers or does not have them; pympp's EVM charge does, and they
prevent double payment or wrong retry semantics. Tests: `tests/evm/test_server_settlement.py` and
the `pympp#320` section of `tests/x402/test_x402_evm_charge.py`.

| Behaviour | Notes |
|---|---|
| Replay claims | `charge(store=AtomicStore)` claims `mpp:evm:authorization:<chain>:<currency>:<from>:<nonce>` (lowercased) with `mpp.store.try_claim` before settling, until `validBefore + 60s`. A replay is `CredentialReplayedError` (403, no `WWW-Authenticate`, no `PAYMENT-REQUIRED`); `validate` reports a live claim as a replay before asking the facilitator. Without a store a bounded in-process `ClaimCache` (1,000,000 live claims, pruned on expiry) is used and a warning is emitted once; when full it refuses with `InternalPaymentError` and never evicts a live claim. A `VerificationFailedError`/`InvalidPayloadError` from settlement releases the claim; any other outcome keeps it. |
| Validity cap | `max_validity_seconds` (default 3600, must be >= `x402.max_timeout_seconds`): `validBefore` beyond now + cap is rejected (`valid for too long`). A native credential may also run to its challenge's expiry. |
| No retry challenge when funds may have moved | `EvmHttpTransport` answers `InternalPaymentError` with a bare 500 problem (no `WWW-Authenticate`, no `PAYMENT-REQUIRED`): facilitator outages (`FacilitatorError` on verify or settle), unreadable settle responses, `errorReason: "settlement_pending"`, `success: true` without a transaction, a settle hook returning no reference, unexpected hook exceptions (reported through `payment.failed`) and a full claim cache. |
| Header codec limits | x402 headers over 64 KiB, nested deeper than 64 levels, carrying lone surrogates, integers beyond 2**53 or non-finite numbers are `InvalidJsonHeaderError` (with a `reason`; the message stays mppx's). |
| Malformed `PAYMENT-SIGNATURE` | `MalformedCredentialError` (`invalid PAYMENT-SIGNATURE header: <reason>`, for example `x402Version must be 2`), also on composed routes. |
| Comparisons | Echoed `accepted` compares `asset`/`payTo` case-insensitively and everything else strictly (`true` never equals `1`). Challenge-hash and route-bound nonces compare case-insensitively; the source is parsed as `did:pkh` with a case-insensitive address. A `null` `extra` stays rejected at decode, as zod does. |
| Payload ranges | `value`/`validAfter`/`validBefore` longer than 78 digits or above uint256 are `InvalidPayloadError` (402). Malformed x402 authorizations converted to native payloads are `InvalidPayloadError` too. |
| Facilitator client | `HttpFacilitator(url, client=, headers=)`: static or sync/async per-request headers; JSON error bodies are read; network errors, non-JSON bodies and malformed responses raise `mpp.x402.facilitator.FacilitatorError`. |
| Client | The EVM client refuses to sign zero-amount native charges. |
