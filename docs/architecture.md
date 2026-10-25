# Architecture

pympp implements the "Payment" HTTP authentication scheme (MPP, HTTP 402) in Python. It
rewrites pympp onto the engine model of the TypeScript reference SDK
[mppx](https://github.com/wevm/mppx) and keeps mppx's **behaviour** (wire formats, defaults,
validation, error types, retries, idempotency, event order) while using ordinary Python
structure. Where the spec ([tempoxyz/mpp-specs](https://github.com/tempoxyz/mpp-specs)) is
ambiguous or says nothing, mppx behaviour wins. The `mpp-tools` conformance suite in
`vendor/mpp-tools` acts as the external check. The feature scope is what pympp 0.15 offers (see
[coverage.md](coverage.md#scope)).

- [Package structure](#package-structure)
- [Core abstractions](#core-abstractions)
- [mppx → Python mapping](#mppx--python-mapping)
- [Writing a custom payment method](#writing-a-custom-payment-method)
- [Internals reference](#internals-reference) (core contract, Tempo primitives)

## Package structure

Distribution `pympp`, import package `mpp`. Modules whose names start with `_` are private (see
[public-sdk-considerations.md](public-sdk-considerations.md#public-api-surface)).

```
src/mpp/
├── __init__.py            Core primitives: Challenge, Credential, Receipt, Method/ClientMethod/
│                          ServerMethod + hook contexts, error classes, Store protocols
├── challenge.py           Challenge (WWW-Authenticate), HMAC challenge ids (compute_id)
├── credential.py          Credential (Authorization: Payment <b64url>)
├── receipt.py             Receipt (Payment-Receipt)
├── payment_request.py     `request` auth-param codec (base64url of RFC 8785 JCS)
├── method.py              Method definition + client/server hook bundles and contexts
├── errors.py              PaymentError hierarchy → RFC 9457 problem details
├── expires.py             Expiry helpers (seconds()…years(), ensure())
├── body_digest.py         `digest` (sha-256=…) compute/verify
├── constants.py           Header names, scheme, built-in method/intent names
├── store.py               Async Store/AtomicStore protocols + memory/redis/kv/prefixed stores
├── mcp.py                 MCP payment codes, meta keys, payment_capabilities
├── py.typed               PEP 561 marker
├── server/                Server engine: Mpp, route handlers, compose, HTTP transport,
│   │                      framework-neutral Request/Response, events
│   └── starlette.py       Starlette/FastAPI @paid (needs [asgi])
├── client/                Client engine: Mpp (httpx transport), protocols (mpp, x402),
│                          events, manual prepare/create flows
├── tempo/                 Tempo charge (needs [tempo]; transactions and signing on pytempo)
│   ├── methods.py         charge Method definition (pydantic schemas)
│   ├── server/            charge offers, fee sponsorship, relay
│   ├── client/            charge, secp256k1 accounts and access keys
│   └── chains.py assets.py attribution.py proof.py
├── stripe/                Stripe SPT charge (client, server), machine payments (`create`)
├── evm/                   Generic EVM charge (EIP-3009 authorization) serving MPP and x402
│                          clients, assets, tokens, chains
├── x402/                  x402 v2 interop: wire types, header codecs, client protocol,
│                          facilitator client
└── mcp_sdk/               Official `mcp` SDK integration: server transport/@paid, McpClient
```

Optional dependencies are imported only by the subpackages that need them. `import mpp`,
`mpp.server`, `mpp.client`, `mpp.store`, `mpp.stripe` and `mpp.x402` all work with the base
install (`httpx` + `pydantic`).

## Core abstractions

### Protocol primitives (`mpp`)

| Type | Wire form | Key API |
|---|---|---|
| `Challenge` | `WWW-Authenticate: Payment id=…, realm=…, method=…, intent=…, request=…` | `Challenge.create(..., secret_key=)` (HMAC id), `Challenge.for_method(method, ...)`, `.serialize()`, `Challenge.deserialize()` / `deserialize_list()`, `.to_dict()` / `from_dict()`, `.verify(secret_key)` |
| `Credential[P]` | `Authorization: Payment <base64url JSON>` | `.serialize()`, `Credential.deserialize()`, `Credential.from_headers(headers)`, `.with_payload()` |
| `Receipt` | `Payment-Receipt: <base64url JSON>` | `.serialize()`, `Receipt.deserialize()`, `Receipt.from_headers()`, `.to_dict()` / `from_dict()` |

All three are frozen dataclasses (`slots=True, kw_only=True`). Python attributes use snake_case;
wire JSON keys stay camelCase exactly as the spec and mppx define them. Parse errors raise
`ValueError` subclasses.

### Methods

A payment method is split into three objects:

- **`Method`**: the definition shared by both sides. It holds the wire `name`/`intent` plus a
  pydantic `request_model` and `payload_model`. The wire request is always
  `request_model.model_validate(input).model_dump(mode="json", by_alias=True, exclude_none=True)`,
  so input transforms (decimal amount → base units, options → `methodDetails`) are pydantic
  validators/serializers. They play the role of mppx's zod transforms.
- **`ClientMethod`**: `create_credential(CredentialParams) -> str` (async). Optional hooks:
  `can_handle_challenge`, `context` (pydantic model for per-request context), `prepare` (runs
  before credential creation, mppx `MethodChallenge`), `handle_response` (post-processes a paid
  response, mppx `MethodResponse`) and `transaction_hash` (feeds `PaymentOutcomeUnknownError`).
- **`ServerMethod`**: either `verify`, or `validate` + `broadcast` (two phases, so standalone
  validation never mutates payment state). Lifecycle hooks: `resolve_request` (mppx `request`
  hook), `authorize` (credential-less access), `preflight`, `respond` (management responses),
  `can_offer`, `on_payment_success`, `stable_binding`. Other fields: `defaults`, `alias`,
  `extensions` and `transport`. Each hook receives one frozen context dataclass and may be sync
  or async. If a hook raises an error that is not a `PaymentError`, the server returns a generic
  `InternalPaymentError` (500).

### Server engine (`mpp.server`)

`Mpp(methods=[...], realm=None, secret_key=None, requires_auth=False, transport=None)` builds
route handlers:

```python
from mpp.server import Mpp, Request, Response


async def handle(mpp: Mpp, request: Request) -> Response:
    handler = mpp.charge(amount="0.01")  # intent shorthand (implicit compose if several)
    # same offers: mpp["tempo/charge"](amount="0.01") or mpp.tempo.charge(amount="0.01")
    result = await handler(request)
    if result.status == 402:
        return result.challenge  # 402 with WWW-Authenticate (+ problem details body)
    return result.with_receipt(Response.json({"data": "paid"}))  # adds Payment-Receipt
```

- The secret comes from `secret_key` or `MPP_SECRET_KEY` and must be at least 32 bytes. The
  realm comes from `realm`, then `MPP_REALM` (plus platform host variables), then the request
  hostname, then `"MPP Payment"`.
- Use `compose(...)` / `mpp.compose(...)` to offer several methods on one route.
  `await mpp.challenge.<method>.<intent>(...)` returns a bare `Challenge`, and
  `verify_credential` / `validate_credential` / `broadcast_credential` cover non-HTTP flows.
- Events: `mpp.on("challenge.created" | "payment.success" | "payment.failed" | "*", fn)`
  returns an unsubscribe function. Handlers have set semantics, so registering the same
  function twice runs it once.
- Transports subclass `Transport[Input, ChallengeOut, ReceiptIn, ReceiptOut]`. Built-ins:
  `http()` (default), `mpp.mcp_sdk.server.mcp_sdk()` and the EVM method's `EvmHttpTransport`
  (native MPP plus x402 on one route), which a `ServerMethod` selects through its `transport`
  field.
- `Request` and `Response` are small framework-neutral types (`httpx.Headers`, bytes or
  async-iterable bodies). `mpp.server.starlette` adapts them (`@paid`, `to_request`,
  `to_starlette`, `from_starlette`).

### Client engine (`mpp.client`)

`Mpp(methods=[...], transport=None, inner=None, on_challenge=None, max_payment_retries=3,
order_challenges=None, payment_preferences=None, accept_payment_policy="always",
allowed_origins=None)`:

- `await mpp.fetch(url, method=..., **httpx_kwargs, context=None)` pays 402s automatically.
  There is no default timeout. Pre-payment redirects are followed. A redirect that answers a
  paid request is returned unfollowed.
- `mpp.payment_transport` is an `httpx.AsyncBaseTransport` you can plug into your own
  `httpx.AsyncClient`. `mpp.client(**kwargs)` builds one that follows mppx's redirect rule.
- `allowed_origins` limits automatic payment to exact HTTP(S) origins. A 402 from another
  origin, checked on the URL that returned it, is returned unchanged.
- Manual flows: `prepare_payment`, `prepare_request`, `create_credential`.
- Protocols: `mpp()` and the x402 protocol. Implement `mpp.client.Protocol`
  (`get_challenges`, `set_credential`) to add one.
- Events: `challenge.received` (a handler may return a credential), `credential.created`,
  `payment.response`, `payment.failed`, `*`.

### Stores (`mpp.store`)

`Store` (`async get/put/delete`) and `AtomicStore` (+ `async update(key, fn)` where `fn` returns
`Noop`/`Set`/`Delete`) are protocols. Values are JSON round-tripped. Built-ins: `memory()`
(single process), `redis(client)` (`redis.asyncio`, atomic), `kv(string_kv)` (adapter for any
async string KV) and `prefixed(store, prefix)`. `try_claim(store, key, expires_ms)` is the
replay-claim primitive (mppx `Store.tryClaim`). Tempo replay claims and recovery records use
mppx's keys and JSON shape, so Python and TypeScript servers can share one store.

## mppx → Python mapping

| mppx | pympp | Why |
|---|---|---|
| `Mppx.create({...})` (server and client) | `mpp.server.Mpp(...)`, `mpp.client.Mpp(...)` | Plain constructors with keyword-only arguments. |
| camelCase options | snake_case kwargs (wire keys unchanged) | PEP 8. Route options also accept camelCase where mppx users pass wire-shaped dicts. |
| zod schemas | pydantic v2 models | Validation plus transforms. Error *types* match mppx; pydantic messages differ from zod text. |
| Plain objects for primitives | frozen, slotted, kw-only dataclasses | Immutable value types. |
| Promises / sync-or-thenable | `async def` for anything that may do I/O; hooks may be sync or async | Async-only API. There is no sync client. |
| `fetch` + `Request`/`Response` | `httpx` on the client; framework-neutral `mpp.server.Request`/`Response` on the server, with a Starlette adapter | No global fetch to patch, so `polyfill`/`restore` have no equivalent. |
| `AbortSignal` | asyncio task cancellation | A cancellation after a credential was sent emits `payment.failed` with `PaymentOutcomeUnknownError`. |
| Symbols/brands (x402 challenges, x402 credentials) | Non-wire `Challenge.protocol`, `Credential` subclasses | No symbols in Python. |
| viem clients and accounts | `mpp.tempo.RpcClient`, `TempoAccount` (`secp256k1_account`, optionally an access key), built on pytempo; `eth-account` for EVM | No web3.py dependency. RPC clients carry no static chain, so the chain is learned once via `eth_chainId` (cached). |
| `console.warn` | `logging` (`mpp.server`, `mpp.client`, `mpp.tempo`, `mpp.stripe`) and `warnings.warn` for the in-memory fallback store | Standard Python channels. |
| Optional peer deps | Extras plus lazy imports | `import mpp` never pulls in chain or framework libraries. |

## Writing a custom payment method

This example defines a complete method and runs it in-process, with the server behind a
Starlette route and the client paying automatically. It needs the `asgi` extra:

```python
import asyncio
from datetime import UTC, datetime

import httpx
from pydantic import BaseModel, ConfigDict
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from mpp import ClientMethod, Credential, Method, Receipt, ServerMethod, VerifyContext
from mpp.client import Mpp as Client
from mpp.errors import VerificationFailedError
from mpp.server import Mpp as Server
from mpp.server.starlette import paid


# 1. Shared definition: wire name/intent + pydantic models (wire keys stay camelCase).
class VoucherRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: str
    currency: str


class VoucherPayload(BaseModel):
    code: str


voucher = Method(
    name="voucher", intent="charge", request_model=VoucherRequest, payload_model=VoucherPayload
)


# 2. Server side: verify the credential and return a receipt (or raise a PaymentError).
async def verify(context: VerifyContext[VoucherPayload]) -> Receipt:
    if context.credential.payload.code != "LET-ME-IN":
        raise VerificationFailedError(reason="unknown voucher code")
    return Receipt(
        method="voucher",
        reference=context.credential.challenge.id,
        timestamp=datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )


server = Server(methods=[ServerMethod(method=voucher, verify=verify)], secret_key="s" * 32)


@paid(server.charge(amount="5", currency="credits"))
async def premium(request):
    return PlainTextResponse("paid content")


app = Starlette(routes=[Route("/premium", premium)])


# 3. Client side: turn the selected challenge into a serialized credential.
async def create_credential(params) -> str:
    return Credential(challenge=params.challenge, payload={"code": "LET-ME-IN"}).serialize()


async def main() -> None:
    client = Client(
        methods=[ClientMethod(method=voucher, create_credential=create_credential)],
        inner=httpx.ASGITransport(app=app),
    )
    async with client:
        response = await client.fetch("http://testserver/premium")
    print(response.status_code, response.text, response.headers["Payment-Receipt"][:16])


asyncio.run(main())
```

Notes:

- `context.credential.payload` is the validated **model instance**. `context.request` is the
  resolved route input. The echoed wire request is `context.credential.challenge.request`.
- Use `validate=` + `broadcast=` instead of `verify=` when settlement is irreversible, so
  `Mpp.validate_credential` can check a credential without spending it.
- Use replay protection for one-time payments: claim a key with
  `await mpp.store.try_claim(store, key, expires_ms)` and raise `CredentialReplayedError` when
  the claim fails.

## Internals reference

This section folds in the internal contracts the SDK was built against. Everything named
here without a leading underscore is importable from the package shown. `_internal` and `_*`
modules are private and may change without notice. They are documented here for contributors.

### Core contract details

- `Challenge.create(*, realm, method, intent, request, id=None | secret_key=None, description,
  digest, expires (str | datetime), header, meta, opaque)` computes the HMAC id with
  `mpp.challenge.compute_id(secret_key, *, realm, method, intent, request, expires, digest,
  header, opaque)`. `Challenge.protocol` is a non-wire tag (`"x402"` for synthesized x402
  challenges) and is ignored by `==`.
- `Receipt(method, reference, timestamp, status="success", external_id, subscription_id,
  funding_currency, extra)`. `extra` holds method extension fields under their wire keys.
- `mpp.payment_request.serialize/deserialize/from_method`. `mpp.expires.seconds…years(n)`,
  `ensure(expires, challenge_id=None)`, `now()` (single clock, patch it in tests).
  `mpp.body_digest.compute/verify`.
- `mpp.constants`: `Header` (`AUTHORIZATION`, `PAYMENT_AUTHORIZATION`, `PAYMENT_RECEIPT`,
  `WWW_AUTHENTICATE`, `ACCEPT_PAYMENT`, …), `PAYMENT_SCHEME`, `MethodName`, `Intent`,
  `MethodDetailKey`.
- `mpp.mcp`: `PAYMENT_REQUIRED_CODE` (-32042), `PAYMENT_VERIFICATION_FAILED_CODE` (-32043),
  `CREDENTIAL_META_KEY`, `RECEIPT_META_KEY`, `PAYMENT_REQUIRED_META_KEY`, `error_code`,
  `parse_credential`, `payment_capabilities` (`capabilities.experimental.payment` for an MCP
  server).
- Server hook contexts: `VerifyContext(credential, request, envelope)`, where
  `envelope.request` is the authoritative wire request and `envelope.captured_request` is a
  `CapturedRequest(method, url, headers, has_body)`.
  `ValidateContext(..., operation="validate" | "broadcast") -> Validation(challenge, credential,
  details, intent, method, request, payer, source)`, `RequestContext(request, captured_request,
  credential)`, `AuthorizeContext(challenge, input, request) -> AuthorizeResult(receipt,
  response)`, `PreflightContext(...)` (returns a 402 for a challenge or another response for a
  management response), `RespondContext(...)`, `CanOfferContext(input, request)`,
  `PaymentSuccessHookContext(receipt, request, challenge, input, payer, request_input)`.
- Client hook params: `CredentialParams(challenge, context, attempt)`. `attempt` is set only
  when the method has `handle_response`. `PrepareParams(challenge, context, send, request)`
  receives the raw, unvalidated `context`. `ResponseParams(challenge, credential, send,
  headers, request, response, refetch)`. `send(httpx.Request)` uses the raw (non-paying)
  transport and returns streaming responses.
- Every configured or composed handler exposes `.offers` (`OfferInfo(method, request, options,
  meta, description, credential_headers, transport)`). `PaymentVerified.has_management_response`
  and `.supports_streaming_receipts` tell framework adapters how to finish a request.
- Route scope binding: adapters bind challenges to `"METHOD /route/path"` (including mount
  prefixes) unless the handler configures `scope` or `meta._mppx_scope`. `mcp_sdk()` binds them
  to `"tool:<name>"`.
- Client per-request options travel as httpx request extensions `"mpp.context"` and
  `"mpp.order_challenges"`. `set_credential_header` purges stale credential headers, including
  `PAYMENT-SIGNATURE`.

### Tempo primitives

These are ported from mppx `src/tempo/internal/*` and the ox `tempo/*` envelope code, on top of
[pytempo](https://pypi.org/project/pytempo/), which models, hashes, signs and encodes Tempo
transactions. Hex values (addresses, hashes, calldata) are `0x` `str`, quantities are `int` and
signer digests are `bytes`. Dependencies are pytempo, `eth-account`/`eth-abi`/`rlp` and
`cryptography`, with no web3.py.

| Module | Contents |
|---|---|
| `mpp.tempo.methods` | The `charge` `Method`. Its request model takes decimal `amount` + `decimals` and dumps base units plus `methodDetails`. |
| `mpp.tempo.chains` | `MAINNET_CHAIN_ID` (4217), `TESTNET_CHAIN_ID` (42431), `RPC_URLS`, `CHAINS`, `resolve_chain_id`, system contract addresses. |
| `mpp.tempo.assets` | `DECIMALS` (6), `Token`, `OUSD`, `PATH_USD`, `USDC_E`, `DEFAULT_CURRENCIES`, `resolve_currency`. |
| `mpp.tempo.attribution` | MPP memo `encode/decode`, `verify_server`, `verify_challenge_binding`. |
| `mpp.tempo.proof` | EIP-712 `MPP` v3 proof `typed_data`/`hash`, `proof_source`, `parse_pkh_source`. |
| `_internal.envelope` | Decoding `0x76` transactions and `0x78` fee-payer envelopes into pytempo models, encoding the `0x78` envelope, key authorizations pytempo cannot model, ox's validation rules and messages. Byte-for-byte equal to ox (fixtures in `tests/tempo/foundations`). |
| `_internal.signature`, `account` | Signature envelopes pytempo lacks (parsing, P256/WebAuthn/keychain/multisig envelopes for verification, RPC formatting) and `TempoAccount` (secp256k1 root keys and access keys). |
| `_internal.rpc` | `RpcClient(url, *, http=None, headers=None, timeout=10, polling_interval=1, retry_count=3, retry_delay=0.15)`: retries like viem's `http` transport. Broadcasts are never retried. |
| `_internal.charge`, `fee_payer`, `fee_token`, `proof` | Transfer/memo matching, sponsor policy and co-signing, fee-token selection, zero-amount proof verification. |

Typical server flow for a signed transaction credential: `deserialize` → `assert_transfer_calls`
+ `assert_challenge_bound_call_memo` → for sponsored transactions `prepare_sponsored_transaction`
+ `sign_as_fee_payer` → `send_raw_transaction_sync` → `assert_transfer_logs` +
`assert_challenge_bound_memo`.
