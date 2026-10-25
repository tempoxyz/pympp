# Migrating from pympp 0.15

This release rewrites pympp onto the engine model of the TypeScript reference SDK
[mppx](https://github.com/wevm/mppx): route handlers, method objects with hooks, and
transports. The wire protocol is unchanged. Challenges, Credentials and Receipts interoperate
with pympp 0.15, mppx and any spec-compliant peer, and the feature scope is what pympp 0.15
offers: Tempo charge, Stripe charge, EVM charge with x402 serving, MCP, replay stores, events
and the payment-aware client. Most Python APIs changed.

Every "before" snippet on this page runs against pympp 0.15.0. Every "after" snippet runs against
this release.

- [At a glance](#at-a-glance)
- [Python and dependencies](#python-and-dependencies)
- [Module map](#module-map)
- [Before / after](#before--after): [server](#server-setup), [route protection](#route-protection),
  [manual handling](#framework-neutral-handling), [composition](#multiple-methods-and-composition),
  [client](#client), [custom methods](#custom-methods), [stores](#stores), [events](#events),
  [errors](#errors), [EVM and x402](#evm-and-x402), [MCP](#mcp), [Stripe](#stripe)
- [Renamed APIs](#renamed-apis)
- [Dropped from 0.15](#dropped-from-015)
- [Behavioural changes](#behavioural-changes)

## At a glance

| | pympp 0.15 | This release |
|---|---|---|
| Install | `pip install "pympp[tempo]"` | `pip install "pympp[tempo]"` |
| Import | `import mpp` | `import mpp` |
| Python | ≥ 3.11 | ≥ 3.12 |
| Server entry point | `Mpp.create(method=…)` + `await server.charge(authorization, amount)` | `Mpp(methods=[…])` + `await mpp.charge(amount=…)(request)` |
| Route decorator | `@server.pay(amount=…)` → `handler(request, credential, receipt)` | `@paid(mpp.charge(amount=…))` from `mpp.server.starlette` |
| Client | `Client(methods=[…]).get(url)` | `Mpp(methods=[…]).fetch(url)` from `mpp.client` |
| Tempo | `tempo(intents={"charge": ChargeIntent()}, …)` | `mpp.tempo.server.charge(…)` / `mpp.tempo.client.charge(…)` |
| EVM / x402 | `evm(currency=BASE_USDC, facilitator=…)` (client and server in one object) | `mpp.evm.server.charge(…, x402=X402Options(…))` / `mpp.evm.client.charge(…)` |
| Method model | `Method` + `Intent`/`VerifiableIntent` protocols, optional `parse_amount` | `Method` (pydantic schemas) + `ClientMethod` / `ServerMethod` hook bundles |
| MCP | `mpp.extensions.mcp` on `mcp>=1.1,<2` (FastMCP) | `mpp.mcp_sdk` on `mcp>=2.3` (`MCPServer`) |
| Secret key | `MPP_SECRET_KEY`, any length | `MPP_SECRET_KEY`, **at least 32 bytes** |
| Default realm | env (`MPP_REALM` + platform variables) → `"localhost"` | env (`MPP_REALM` + platform variables) → request host → `"MPP Payment"` |

## Python and dependencies

- Python 3.11 is no longer supported. CI tests 3.12, 3.13 and 3.14.
- Base dependencies changed from `httpx` + `rfc8785` to `httpx` + `pydantic`. JCS
  canonicalization is built in.
- The import package is still `mpp`.

| pympp 0.15 extra | Contents | This release |
|---|---|---|
| `tempo` | `pytempo>=0.2.1`, `pydantic`, `eth-account`, `eth-abi`, `eth-hash`, `attrs`, `rlp`, pins (`pyjwt`, `propcache`, `urllib3`, `yarl`) | `tempo`: `pytempo>=0.6.1`, `eth-account`, `eth-abi`, `rlp`, `cryptography`. pytempo stays the transaction and signing library. No transitive pins. |
| `stripe` | the `tempo` set + `stripe>=8` | **Removed.** `mpp.stripe` works with the base install over plain `httpx` and does not need the Stripe SDK. Add `tempo` for the machine-payment Tempo rail. |
| `evm` | `eth-account`, `eth-hash` | `evm`: `eth-account`, `eth-abi` |
| `server` | `pydantic` | **Removed.** pydantic is a base dependency. |
| `redis` | `redis>=5.0` | `redis`: `redis>=5.2` |
| `sqlite` | `aiosqlite` | **Removed** together with `SQLiteStore`. See [Stores](#stores). |
| `mcp` | `mcp>=1.1,<2`, `anyio`, `uvicorn` pin, … | `mcp`: `mcp>=2.3` (official SDK 2.x: `MCPServer`, `MCPError`) |
| | | New: `asgi` (`starlette`, for `mpp.server.starlette`) |

## Module map

| pympp 0.15 | This release |
|---|---|
| `mpp` (`Challenge`, `ChallengeEcho`, `Credential`, `Receipt`) | `mpp` (`Challenge`, `Credential`, `Receipt`). `ChallengeEcho` is gone: a Credential carries the full `Challenge`. |
| `mpp` (`parse_*` / `format_*`, `generate_challenge_id`, `ParseError`) | `Challenge/Credential/Receipt.deserialize()` / `.serialize()`, `mpp.challenge.compute_id`. Parse errors are `ValueError`. |
| `mpp.Expires`, `mpp.BodyDigest` | `mpp.expires`, `mpp.body_digest` |
| `mpp.errors` | `mpp.errors` (also re-exported from `mpp`) |
| `mpp.events` (`PaymentEventName`, `EventDispatcher`, payload TypedDicts) | Event names are plain strings. Payload dataclasses live in `mpp.server` (`ChallengeCreated`, `PaymentSucceeded`, `PaymentFailed`, `EventEnvelope`) and `mpp.client` (`ChallengeReceived`, `CredentialCreated`, `PaymentResponse`, `ClientPaymentFailed`, `ClientEventEnvelope`). |
| `mpp.store` (`Store`, `MemoryStore`, `ExpiringStore`), `mpp.stores` (`RedisStore`, `SQLiteStore`) | `mpp.store` (`Store`, `AtomicStore`, `memory()`, `redis()`, `kv()`, `prefixed()`, `try_claim()`) |
| `mpp.server` (`Mpp`, `pay`, `verify_or_challenge`, `compose`, `Intent`, `VerifiableIntent`, `intent`, `Method`, `validate_credential`, `broadcast_credential`) | `mpp.server` (`Mpp`, `compose`, `Request`, `Response`, `Transport`, events), `mpp.server.starlette` (`paid`), `mpp` (`Method`, `ServerMethod`, `validate_credential`, `broadcast_credential`) |
| `mpp.client` (`Client`, `PaymentTransport`, `get`, `post`, `request`), `mpp.runtime` (`PaymentRuntime`) | `mpp.client` (`Mpp`: `fetch`, `client()`, `payment_transport`, `prepare_payment`, `create_credential`), `mpp` (`ClientMethod`) |
| `mpp.methods.tempo` (`tempo`, `ChargeIntent`, `TempoAccount`, `Relay`, `Split`, `parse_pkh_source`, constants) | `mpp.tempo.server` (`charge`, `tempo`, `RelayOptions`, `FeePayerPolicy`, `RemoteFeePayer`, …), `mpp.tempo.client` (`charge`, `tempo`, `secp256k1_account`, …), `mpp.tempo.chains`, `mpp.tempo.assets`, `mpp.tempo.methods`, `mpp.tempo.proof` (`parse_pkh_source`) |
| `mpp.methods.tempo.attribution` | `mpp.tempo.attribution` |
| `mpp.methods.evm` (`evm`, `BASE_USDC` and other assets, `ChargeIntent`) | `mpp.evm.server` (`charge`, `evm`, `X402Options`), `mpp.evm.client` (`charge`), `mpp.evm.assets` (`BASE_USDC`, …) |
| `mpp.x402` (header codecs, wire types, `X402Intent`, facilitator) | `mpp.x402` (header codecs, wire types, facilitator, client protocol). Serving x402 clients is built into `mpp.evm.server.charge(x402=…)`. |
| `mpp.methods.stripe` (`spt`, `stripe`, `ChargeIntent`, `create`, `MachinePayments`, `PaymentIntentOptions`, …) | `mpp.stripe.server` (`charge` = `spt`, `create`, `MachinePayments`, …), `mpp.stripe.client` (`charge`), `mpp.stripe` (schemas, `StripeHttpClient`, `PaymentIntentOptions`) |
| `mpp.extensions.mcp` | `mpp.mcp` (codes, meta keys, `payment_capabilities`), `mpp.mcp_sdk.server` (`mcp_sdk`, `paid`), `mpp.mcp_sdk.client` (`McpClient`) |

## Before / after

### Server setup

Before:

```python
import os

from mpp.methods.tempo import PATH_USD, ChargeIntent, TempoAccount, tempo
from mpp.server import Mpp

server = Mpp.create(
    method=tempo(
        intents={"charge": ChargeIntent(chain_id=42431)},
        recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        chain_id=42431,  # Moderato
        fee_payer=TempoAccount.from_key(os.environ["FEE_PAYER_KEY"]),
        allowed_fee_tokens=[PATH_USD],
    ),
    secret_key=os.environ["MPP_SECRET_KEY"],
)
```

After:

```python
import os

from mpp.server import Mpp
from mpp.tempo import server as tempo
from mpp.tempo.assets import PATH_USD_ADDRESS
from mpp.tempo.server import secp256k1_account

mpp = Mpp(
    methods=tempo.charge(  # one ServerMethod per accepted currency
        recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        testnet=True,  # Moderato
        fee_payer=secp256k1_account(os.environ["FEE_PAYER_KEY"]),
        allowed_fee_tokens=[PATH_USD_ADDRESS],
    ),
    secret_key=os.environ["MPP_SECRET_KEY"],  # must be >= 32 bytes
)
```

- Options that used to be split across `tempo(...)` and `ChargeIntent(...)` are all keyword
  arguments of `tempo.charge(...)`: `recipient`/`account`, `fee_payer`, `allowed_fee_tokens`,
  `fee_token`, `fee_payer_policy`, `currencies`, `chain_id`/`testnet`, `store`,
  `validate_sender`, `confirmation_timeout_ms` (was `confirmation_timeout` in seconds), `relay`,
  `can_offer` and `on_payment_success`.
- `methods=` takes a flat or nested list, so `methods=[tempo.charge(...), stripe.charge(...)]`
  works as written.
- To point Tempo at another RPC endpoint, pass `get_client=lambda chain_id: RpcClient(url)`
  (`from mpp.tempo import RpcClient`). `ChargeIntent(rpc_url=..., http_client=..., timeout=...)`
  is gone.
- `Mpp(defaults=...)` is gone. Use per-method defaults such as `tempo.charge(amount=...)` or
  `ServerMethod(defaults=...)`.

### Route protection

Before:

```python
from fastapi import FastAPI, Request

from mpp import Credential, Receipt

app = FastAPI()


@app.get("/premium")
@server.pay(amount="0.01")
async def premium(request: Request, credential: Credential, receipt: Receipt) -> dict[str, str]:
    return {"data": "paid content", "payer": receipt.payer or ""}
```

After:

```python
from fastapi import FastAPI

from mpp.server import PaymentSucceeded
from mpp.server.starlette import paid

app = FastAPI()


@app.get("/premium")
@paid(mpp.charge(amount="0.01"))
async def premium() -> dict[str, str]:
    return {"data": "paid content"}  # Payment-Receipt is added to the response


def on_success(event: PaymentSucceeded) -> None:  # receipt and payer arrive as an event
    print("paid", event.receipt.reference, event.payer)


mpp.on_payment_success(on_success)
```

- The endpoint no longer receives `credential` and `receipt` arguments, and `Receipt` has no
  `payer`. Use the `payment.success` event (`PaymentSucceeded.receipt`, `.payer`,
  `.credential`, `.input`), or call the handler yourself (next section).
- `@paid` adds `Payment-Receipt` to any response, including plain data the framework
  serializes.
- The endpoint may declare a `Request` parameter or not, and may return a Starlette `Response`,
  any FastAPI-serializable value, or an async iterable (streamed).
- `server.pay(expires_in=timedelta(...))` becomes `mpp.charge(expires=...)` (a `datetime` or
  ISO string, or `None` to omit expiry).

### Framework-neutral handling

Before:

```python
from mpp import Challenge
from mpp.server import ComposedChallenges


async def handle(authorization: str | None):
    result = await server.charge(authorization, "0.01")
    if isinstance(result, Challenge | ComposedChallenges):
        challenges = result.challenges if isinstance(result, ComposedChallenges) else (result,)
        return 402, [c.to_www_authenticate(server.realm) for c in challenges]
    credential, receipt = result
    return 200, receipt.to_payment_receipt()
```

After:

```python
from mpp.server import Request, Response


async def handle(request: Request) -> Response:
    result = await mpp.charge(amount="0.01")(request)
    if result.status == 402:
        return result.challenge  # 402 + one WWW-Authenticate per offer + problem details
    return result.with_receipt(Response.json({"data": "paid content"}))
```

- Handlers take the whole request (`mpp.server.Request(method, url, headers=, body=)`), not an
  `authorization` string. The engine reads `Authorization` itself, or `Payment-Authorization`
  when `Mpp(requires_auth=True)`, so `payment_authorization=` is gone. It uses the URL for realm
  detection and the body for digest checks.
- The result is `PaymentRequired` (a ready-made 402 `Response` in `.challenge`) or
  `PaymentVerified` (`.with_receipt(response)`). You no longer build `WWW-Authenticate` headers
  or problem bodies yourself.
- `server.charge(..., currency=, recipient=, splits=, fee_payer=, chain_id=, description=,
  expires=, extra=, body=, meta=)` become route options on the handler:
  `mpp.charge(amount=..., description=..., expires=..., meta=..., scope=..., **method_fields)`.
  The body digest is computed from `Request.body`.
- `payment_signature=`, `resource_url=` and `server.x402_payment_required(...)` are gone: the
  EVM method's transport reads `PAYMENT-SIGNATURE` and writes `PAYMENT-REQUIRED` /
  `PAYMENT-RESPONSE` itself (see [EVM and x402](#evm-and-x402)).
- To verify a Credential without HTTP, use `await mpp.verify_credential(credential)`,
  `validate_credential(...)` or `broadcast_credential(...)`.

### Multiple methods and composition

pympp composed implicitly when a method had several currencies, and explicitly through
`server.compose(...)`. In this release:

```python
import os

from mpp.server import Mpp
from mpp.stripe import server as stripe
from mpp.tempo import server as tempo

mpp = Mpp(
    methods=[
        tempo.charge(recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00", testnet=True),
        stripe.charge(
            secret_key=os.environ["STRIPE_SECRET_KEY"],
            network_id="internal",
            payment_method_types=["card"],
            currency="usd",
            decimals=2,
        ),
    ],
)
every_charge = mpp.charge(amount="0.50")  # implicit compose: all "charge" offers
explicit = mpp.compose(
    ("tempo/charge", {"amount": "0.45"}),  # both Tempo currencies
    ("stripe/charge", {"amount": "0.50"}),
)
```

Both handlers are called like any other handler (`await every_charge(request)`) and return one
402 carrying every Challenge, in order.

### Client

Before:

```python
import asyncio
import os

from mpp.client import Client
from mpp.methods.tempo import USDC, ChargeIntent, TempoAccount, tempo


async def main() -> None:
    account = TempoAccount.from_key(os.environ["TEMPO_PRIVATE_KEY"])
    method = tempo(
        account=account,
        intents={"charge": ChargeIntent()},
        currency=USDC,
        max_amount="1.00",
        max_amount_decimals=6,
        expected_recipients=["0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"],
        allowed_chain_ids=[4217],
    )
    async with Client(methods=[method], allowed_origins=["https://api.example.com"]) as client:
        response = await client.get("https://api.example.com/premium")
        print(response.status_code)


asyncio.run(main())
```

After:

```python
import asyncio
import os

from mpp.client import Mpp
from mpp.tempo import client as tempo
from mpp.tempo.assets import USDC_ADDRESS  # USDC.e
from mpp.tempo.client import secp256k1_account


async def main() -> None:
    account = secp256k1_account(os.environ["TEMPO_PRIVATE_KEY"])
    method = tempo.charge(
        account=account,
        currencies=[USDC_ADDRESS],
        max_amount="1.00",
        decimals=6,
        expected_recipients=["0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"],
        allowed_chain_ids=[4217],
    )
    async with Mpp(methods=[method], allowed_origins=["https://api.example.com"]) as mpp:
        response = await mpp.fetch("https://api.example.com/premium")
        print(response.status_code)


asyncio.run(main())
```

| pympp 0.15 | This release |
|---|---|
| `Client(methods=...)`, `client.get/post/put/delete(url, **kw)` | `Mpp(methods=...)`, `await mpp.fetch(url, method="POST", json=..., timeout=...)`, or `mpp.client()` (an `httpx.AsyncClient` with `.get/.post/…`) |
| `get(url, methods=...)` / `post(...)` / `request(...)` | `async with Mpp(methods=...) as m: await m.fetch(...)` |
| `PaymentTransport(methods=..., inner=...)` | `Mpp(methods=..., inner=...).payment_transport` |
| `PaymentRuntime.match_challenge` / `create_credential` | `await mpp.prepare_payment(response)` / `await mpp.create_credential(response)` |
| `max_payment_retries=`, `allowed_origins=` | Same names on `Mpp(...)` |
| `TempoAccount.from_key(k)` / `.from_env()` | `secp256k1_account(k)`. Read the environment variable yourself. |
| `tempo(root_account=ROOT, account=ACCESS_KEY)` | `secp256k1_account(access_key_private_key, access=ROOT)` |
| `tempo(currency=, currencies=, max_amount=, max_amount_decimals=, max_atomic_amount=, expected_recipients=, allowed_chain_ids=)` | `tempo.charge(currencies=, max_amount=, decimals=, max_atomic_amount=, expected_recipients=, allowed_chain_ids=)`, plus `expected_chain_id` |
| `tempo(chain_id=, rpc_url=)` | `tempo.charge(expected_chain_id=, get_client=)` |
| `tempo(client_id=)` | `tempo.charge(client_id=)` |

### Custom methods

Before (a `Method` with an `intents` mapping, an `@intent` verifier and the optional
`parse_amount` hook that owns the wire amount):

```python
from mpp import Credential, Receipt
from mpp.server import Mpp, VerificationError, intent


@intent("charge")
async def verify_voucher(credential: Credential, request: dict) -> Receipt:
    if credential.payload.get("code") != "LET-ME-IN":
        raise VerificationError("unknown voucher code")
    return Receipt.success(reference=credential.challenge.id, method="voucher")


class VoucherMethod:
    name = "voucher"
    currency = "credits"
    recipient = "shop"
    intents = {"charge": verify_voucher}

    def parse_amount(self, amount: str) -> str:  # the wire amount stays "5"
        return amount

    async def create_credential(self, challenge) -> Credential:  # client side
        return Credential(challenge=challenge.to_echo(), payload={"code": "LET-ME-IN"})


server = Mpp.create(method=VoucherMethod(), secret_key="secret")
```

After (one shared `Method` definition with pydantic schemas, a `ServerMethod` with hooks, and
a `ClientMethod` that returns the serialized Credential):

```python
from datetime import UTC, datetime

from pydantic import BaseModel

from mpp import ClientMethod, Credential, Method, Receipt, ServerMethod, VerifyContext
from mpp.errors import VerificationFailedError
from mpp.server import Mpp


class VoucherRequest(BaseModel):  # route input -> wire request; owns the amount format
    amount: str
    currency: str
    recipient: str


class VoucherPayload(BaseModel):  # Credential payload schema
    code: str


voucher = Method(
    name="voucher", intent="charge", request_model=VoucherRequest, payload_model=VoucherPayload
)


async def verify(context: VerifyContext[VoucherPayload]) -> Receipt:
    if context.credential.payload.code != "LET-ME-IN":  # payload is the validated model
        raise VerificationFailedError(reason="unknown voucher code")
    return Receipt(
        method="voucher",
        reference=context.credential.challenge.id,
        timestamp=datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )


server = Mpp(
    methods=[
        ServerMethod(
            method=voucher, verify=verify, defaults={"currency": "credits", "recipient": "shop"}
        )
    ],
    secret_key="s" * 32,
)


async def create_credential(params) -> str:  # client side
    return Credential(challenge=params.challenge, payload={"code": "LET-ME-IN"}).serialize()


client_method = ClientMethod(method=voucher, create_credential=create_credential)
```

| pympp 0.15 | This release |
|---|---|
| `Intent.verify(credential, request)` | `ServerMethod(verify=fn)`, `fn(VerifyContext)` |
| `VerifiableIntent.validate` / `.broadcast` | `ServerMethod(validate=..., broadcast=...)` (two-phase) |
| `parse_amount(amount)`, `transform_request`, `method.decimals` | `request_model` validators and serializers. The wire request is `request_model.model_validate(input).model_dump(by_alias=True, exclude_none=True)`, so the model decides whether `amount` is converted to base units. |
| `prepare_intent(intent, input)` | `resolve_request` hook (`RequestContext`) or route options |
| `can_offer(request)`, `on_payment_success(payload)` attributes | `ServerMethod(can_offer=fn(CanOfferContext), on_payment_success=fn(PaymentSuccessHookContext))` |
| Client `create_credential(challenge) -> Credential` | `ClientMethod(create_credential=fn(CredentialParams) -> str)`, plus optional `can_handle_challenge`, `context` (pydantic model), `prepare`, `handle_response` |
| `credential.payload` dict, `credential.challenge` a `ChallengeEcho` | Server hooks get the validated payload **model**. `credential.challenge` is a full `Challenge` with a decoded `request` dict. |

A complete runnable example, with a server and a paying client, is in
[architecture.md](architecture.md#writing-a-custom-payment-method).

### Stores

Before:

```python
import redis.asyncio as redis

from mpp.methods.tempo import ChargeIntent, tempo
from mpp.server import Mpp
from mpp.stores import RedisStore

server = Mpp.create(
    method=tempo(
        intents={"charge": ChargeIntent()}, recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    ),
    store=RedisStore(redis.Redis.from_url("redis://localhost:6379/0")),
)
```

After (stores go to the method that needs them, not to the server):

```python
import redis.asyncio as redis

from mpp import store
from mpp.tempo import server as tempo

methods = tempo.charge(
    recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
    store=store.redis(redis.Redis.from_url("redis://localhost:6379/0"), key_prefix="mpp:"),
)
```

- The store protocol changed. pympp's `get/put/delete/put_if_absent` (plus
  `ExpiringStore.put_if_absent_until`) is now `get/put/delete` (`Store`) plus atomic
  `update(key, fn)` (`AtomicStore`). Replay protection needs an `AtomicStore`.
  `mpp.store.try_claim(store, key, expires_ms)` replaces `put_if_absent`.
- `RedisStore(client, key_prefix="mpp:", ttl_seconds=...)` is now
  `store.redis(client, key_prefix=...)`. Claims expire on their own (`SET NX PXAT`), so there
  is no store-wide TTL.
- `MemoryStore(max_entries=...)` raised when full. `mpp.store.memory()` is unbounded and only
  protects a single process.
- `SQLiteStore` is removed. Wrap any async string KV with `store.kv(kv)` (not atomic), or
  implement `AtomicStore` (`get/put/delete/update`) over your database.
- Without a `store`, `tempo.charge` and `evm.charge` fall back to an in-memory store and emit a
  `UserWarning` once per method name.
- Keys and records use mppx's layout, so a server on this release and an mppx server can share
  a store. pympp 0.15 keys are not read (see [Dropped from 0.15](#dropped-from-015)).

### Events

Before:

```python
def on_success(payload) -> None:
    print("paid", payload["receipt"].reference, payload["receipt"].payer)


unsubscribe = server.on_payment_success(on_success)
```

After (payloads are frozen dataclasses, `payer` sits on the event, and names are strings):

```python
from mpp.server import PaymentSucceeded


def on_success(event: PaymentSucceeded) -> None:
    print("paid", event.receipt.reference, event.payer)


unsubscribe = mpp.on("payment.success", on_success)  # or mpp.on_payment_success(on_success)
```

- `PaymentEventName`, `CHALLENGE_CREATED` and the other constants are gone. Use the strings
  `"challenge.created"`, `"payment.success"`, `"payment.failed"` and `"*"` on the server, and
  `"challenge.received"`, `"credential.created"`, `"payment.response"`, `"payment.failed"` and
  `"*"` on the client.
- Handlers may be sync or async, and registration has set semantics. Observer exceptions are
  logged and swallowed, as in pympp.
- A client `challenge.received` handler may return a Credential string. `Mpp(on_challenge=fn)`
  runs when no handler supplied one, and an exception raised there aborts the payment.

### Errors

Class names and RFC 9457 `type` URIs are unchanged (`https://paymentauth.org/problems/...`),
including 0.15's `CredentialReplayedError` (403, no new Challenge) and `InternalPaymentError`
(500, generic message). Constructors and a few classes changed:

| pympp 0.15 | This release |
|---|---|
| Positional constructor arguments, for example `VerificationFailedError("reason")` | Keyword-only: `VerificationFailedError(reason=..., details=...)` |
| `InvalidChallengeError(challenge_id=, reason=)` | `InvalidChallengeError(id=, reason=)` |
| `PaymentRequiredError(realm=, description=)` | `PaymentRequiredError(description=)` |
| `VerificationError(message)` (a `VerificationFailedError` with a verbatim message) | Removed. Raise `VerificationFailedError(reason=...)` (`"Payment verification failed: <reason>."`). |
| `PaymentOutcomeUnknownError(challenge, cause, *, credential=, request=, transaction_hash=)` | `PaymentOutcomeUnknownError(*, challenge, credential: str, transaction_hash=None, cause=None)` |
| `error.retry_challenge` | Removed. The engine decides whether to re-issue a Challenge. |
| `mpp.errors.Hints` | Module constants `HINT_PAYMENT_REQUIRED`, `HINT_MALFORMED_CREDENTIAL`, `HINT_METHOD_UNSUPPORTED` |
| `ParseError` | `ValueError` subclasses (`InvalidCredentialEncodingError`, `MissingAuthorizationHeaderError`, `MissingPaymentSchemeError`, …) |
| MCP `McpError` subclasses (`PaymentRequiredError`, `PaymentVerificationError`, `MalformedCredentialError`) | The MCP transport raises the SDK's `MCPError` with codes -32042 / -32043 / -32602 / -32603. `mpp.mcp.error_code(error)` maps a `PaymentError` to its code. |

When a hook raises anything that is not a `PaymentError`, the server answers with a generic
`InternalPaymentError` (500) and logs the cause.

### EVM and x402

Before (one `evm(...)` object serves native MPP and x402 v2 `exact` clients):

```python
from mpp.methods.evm import BASE_USDC, evm
from mpp.server import Mpp

server = Mpp.create(
    method=evm(
        currency=BASE_USDC,
        recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        facilitator="https://facilitator.example.com",
        route_binding="resource",  # accept standard x402 clients on scoped routes
    ),
)
```

After:

```python
from mpp.evm import assets
from mpp.evm import server as evm
from mpp.server import Mpp

mpp = Mpp(
    methods=[
        evm.charge(
            currency=assets.BASE_USDC,
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            x402=evm.X402Options(
                facilitator="https://facilitator.example.com",
                route_binding="resource",
            ),
        )
    ],
)
```

- Facilitator, `max_timeout_seconds` and `route_binding` move into `X402Options`.
  `settle=`, `max_validity_seconds=`, `can_offer=` and `on_payment_success=` stay on
  `charge(...)`, which also takes `store=` for authorization replay claims.
- The method's transport handles both protocols on one route: `PAYMENT-REQUIRED` goes next to
  `WWW-Authenticate`, `PAYMENT-SIGNATURE` is read, and `PAYMENT-RESPONSE` is added to paid x402
  responses. `server.x402_payment_required(...)`, `payment_signature=` and `resource_url=` are
  gone.
- `evm.evm(currencies=[...], ...)` returns one offer per currency.
- The client side is separate: `mpp.evm.client.charge(account=Account.from_key(...),
  currencies=[assets.BASE_USDC], max_amount=...)` replaces `evm(currency=..., account=...,
  max_amount=...)`. It pays native `evm` Challenges and x402 `PAYMENT-REQUIRED` responses.

### MCP

Before (FastMCP 1.x; base-unit amounts; the tool receives `credential`/`receipt`):

```python
from mcp.server.fastmcp import FastMCP

from mpp.extensions.mcp import pay
from mpp.methods.tempo import ChargeIntent

mcp = FastMCP("premium")


@mcp.tool()
@pay(
    tool="search",
    intent=ChargeIntent(chain_id=42431, rpc_url="https://rpc.moderato.tempo.xyz"),
    request={
        "amount": "10000",  # base units
        "currency": "0x20c0000000000000000000000000000000000000",
        "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        "methodDetails": {"chainId": 42431},
    },
    realm="api.example.com",
    secret_key="secret",
)
async def search(query: str, *, credential, receipt) -> str:
    return f"results for {query}"
```

After (official SDK 2.x `MCPServer`; the same `Mpp` engine and methods as HTTP, with MCP as a
transport):

```python
import os

from mcp.server.mcpserver import MCPServer

from mpp.mcp_sdk.server import mcp_sdk, paid
from mpp.server import Mpp
from mpp.tempo import server as tempo

payment = Mpp(
    methods=tempo.charge(recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00", testnet=True),
    transport=mcp_sdk(),
    realm="api.example.com",
    secret_key=os.environ["MPP_SECRET_KEY"],
)
server = MCPServer("premium")


@server.tool()
@paid(payment.charge(amount="0.01"))  # display units; bound to "tool:search"
async def search(query: str) -> str:
    return f"results for {query}"
```

Client:

```python
import asyncio
import os

from mcp import Client

from mpp.mcp_sdk.client import McpClient
from mpp.tempo import client as tempo
from mpp.tempo.client import secp256k1_account


async def main() -> None:
    account = secp256k1_account(os.environ["TEMPO_PRIVATE_KEY"])
    async with Client(server) as session:  # or Client("https://example.com/mcp")
        mcp = McpClient(session, methods=[tempo.charge(account=account)])
        result = await mcp.call_tool("search", {"query": "llamas"})
        print(result.content[0].text, result.receipt.reference)


asyncio.run(main())
```

| pympp 0.15 `mpp.extensions.mcp` | This release |
|---|---|
| `pay(intent=, request=, tool=, realm=, secret_key=, expires_in=)` | `paid(handler)` from `mpp.mcp_sdk.server` with `Mpp(transport=mcp_sdk())` |
| `verify_or_challenge(tool=, meta=, ...)` / `create_challenge(...)` | `result = await payment.charge(...)(ctx)`; `raise result.challenge` / `result.with_receipt(CallToolResult(...))` |
| `tool=` binding | **Automatic.** `mcp_sdk()` binds each Challenge to `tool:<name>` of the called tool. An explicit `scope=` wins. |
| `McpClient(session, methods, trusted_tempo_realms=).call_tool(name, args, timeout=, meta=)` → `McpToolResult` | `McpClient(session, methods=...).call_tool(name, args, read_timeout_seconds, progress_callback, *, meta, context, on_payment_required)` → `PaidCallToolResult` (a `CallToolResult` with `.receipt`). Up to 3 attempts. |
| `MCPChallenge` / `MCPCredential` / `MCPReceipt` | Core `Challenge.to_dict()/from_dict()`, `Credential`, `Receipt`. `mpp.mcp.parse_credential(meta_value)`. |
| `payment_capabilities(methods, intents)` | `mpp.mcp.payment_capabilities(payment)` derives both lists from the server `Mpp` (or its methods). |
| `CODE_PAYMENT_REQUIRED`, `META_CREDENTIAL`, … | `mpp.mcp.PAYMENT_REQUIRED_CODE`, `CREDENTIAL_META_KEY`, … |

### Stripe

Before:

```python
import os

from mpp.methods.stripe import ChargeIntent, spt
from mpp.server import Mpp

server = Mpp.create(
    method=spt(
        intents={"charge": ChargeIntent(secret_key=os.environ["STRIPE_SECRET_KEY"])},
        network_id="internal",
        payment_method_types=["card"],
        currency="usd",
        decimals=2,
        recipient="internal",
    ),
)


async def create_spt(params) -> str:  # client: ask your backend to mint an SPT
    return "spt_123"


client_method = spt(create_token=create_spt, payment_method="pm_card_visa", intents={})
```

After:

```python
import os

from mpp.server import Mpp
from mpp.stripe import client as stripe_client
from mpp.stripe import server as stripe

mpp = Mpp(
    methods=[
        stripe.charge(
            secret_key=os.environ["STRIPE_SECRET_KEY"],  # or client=<StripeClient adapter>
            network_id="internal",
            payment_method_types=["card"],
            currency="usd",
            decimals=2,
        )
    ],
)
handler = mpp.charge(amount="0.50")  # wire amount "50" (cents)


async def create_spt(params: stripe_client.TokenParams) -> str:  # ask your backend for an SPT
    return "spt_123"


client_method = stripe_client.charge(create_token=create_spt, payment_method="pm_card_visa")
```

| pympp 0.15 | This release |
|---|---|
| `spt(...)` / deprecated `stripe(...)` (one object for client and server) | `mpp.stripe.server.charge(...)` (alias `spt`) and `mpp.stripe.client.charge(...)` |
| `ChargeIntent(client=<stripe SDK>)` (duck-typed `payment_intents.create`) | `stripe.charge(client=...)`, where `client` implements `StripeClient.create_payment_intent(params, *, api_version, idempotency_key, stripe_account) -> PaymentIntent`. Wrap your SDK in a small adapter, or pass `secret_key=` (built-in `StripeHttpClient`). |
| `decimals` default 2 | No default. Pass `decimals=` (mppx requires it). |
| `recipient` required by `Mpp.charge` | Optional |
| `payment_intent_options=` per `charge()` call, `PaymentIntentContext` | `mpp.charge(amount=..., payment_intent_options={...} \| resolver)`. Resolvers get `ResolveContext(challenge, credential, envelope, request)`. Passing it to the `stripe.charge()` factory raises `TypeError`, matching mppx's runtime. |
| `create(network_id=, livemode=, client=, store=, deposit_addresses=, metadata=)` → `.spt.charge()`, `.tempo.charge()`, `.default_methods()` | `create(client=StripeHttpClient(key), network_id=, livemode=, store=, deposit_addresses=, metadata=)` → `MachinePayments` with `spt_charge()`, `tempo_charge(recipient=...)`, `find_or_create_deposit_address()`, `default_methods(...)`, `await load_default_methods(...)` |
| `create_token(OnChallengeParameters)` | `create_token(TokenParams(amount, challenge, client, currency, expires_at, metadata, network_id, payment_method))` |

## Renamed APIs

| pympp 0.15 | This release |
|---|---|
| `Mpp.create(method=…/methods=…)` | `Mpp(methods=…)` (plain constructor; the class keeps its name) |
| `server.charge(authorization, amount, …)` | `await mpp.charge(amount=…)(request)` |
| `server.pay(…)` decorator, standalone `pay(intent=, request=)` | `mpp.server.starlette.paid(handler)` |
| `verify_or_challenge(authorization=, intent=, request=, realm=)` | A route handler on an `Mpp` instance |
| `server.compose(…)` / `ComposedHandler.verify(authorization)` | `mpp.compose(…)` / `await handler(request)` |
| `Challenge.from_www_authenticate(h)` / `.to_www_authenticate(realm)` | `Challenge.deserialize(h)` / `deserialize_list(h)` / `.serialize()` (the realm lives on the Challenge) |
| `Challenge.verify(secret_key, realm)` | `Challenge.verify(secret_key)` |
| `Credential.from_authorization(h)` / `.to_authorization()` | `Credential.deserialize(h)` / `.serialize()` / `Credential.from_headers(headers)` |
| `Receipt.from_payment_receipt(h)` / `.to_payment_receipt()` | `Receipt.deserialize(h)` / `.serialize()` / `Receipt.from_headers(headers)` |
| `Receipt.extensions` (unknown top-level keys) | `Receipt.extra` |
| `generate_challenge_id(...)` | `mpp.challenge.compute_id(secret_key, *, realm, method, intent, request, expires, digest, header, opaque)` |
| `Client`, `PaymentTransport`, `PaymentRuntime` | `mpp.client.Mpp` |
| `mpp.methods.tempo.tempo(intents=…)` | `mpp.tempo.server.charge(…)` / `mpp.tempo.client.charge(…)` (`tempo(…)` is the same charge offers) |
| `TempoAccount.from_key` | `mpp.tempo.client.secp256k1_account` (also exported from `mpp.tempo.server`) |
| `Relay(api_key, api_base_url, http_client, timeout)` | `RelayOptions(api_key, api_base_url, http)` → `tempo.charge(relay=…)` |
| `SenderValidation` | `ValidateSenderParams(sender, expected_sender, source)` |
| `default_currencies_for_chain(id)`, `OUSD`, `PATH_USD`, `USDC` | `mpp.tempo.assets.DEFAULT_CURRENCIES`, `OUSD`, `PATH_USD`, `USDC_E` (`Token` objects; `.address(chain_id)`), or the `OUSD_ADDRESS`, `PATH_USD_ADDRESS`, `USDC_ADDRESS` strings |
| `mpp.methods.evm.evm(...)` | `mpp.evm.server.charge(...)` / `evm(...)` and `mpp.evm.client.charge(...)` |
| `mpp.methods.stripe.spt` | `mpp.stripe.server.charge` / `mpp.stripe.client.charge` |
| `mpp.extensions.mcp.pay` | `mpp.mcp_sdk.server.paid` |

## Dropped from 0.15

These pympp 0.15 APIs have no counterpart in this release:

- **Python 3.11.** The code uses 3.12 syntax.
- **trio.** pympp 0.15 reported unknown MCP payment outcomes on trio too. This release runs on
  asyncio only.
- **`SQLiteStore`** and the `sqlite` extra. Use `store.redis(...)` or your own `AtomicStore`.
- **FastMCP 1.x** (`mcp<2`). The MCP integration targets the official SDK 2.x.
- **`unique_challenges=`.** Server-issued Challenges still carry a random HMAC-bound nonce, now
  under mppx's key `_mppx_nonce` instead of 0.15's `_mpp_nonce`, and it can't be turned off. Credentials
  for Challenges issued by a 0.15 server are rejected after the switch.
- **`trusted_tempo_realms`.** 0.15 clients refused zero-amount Tempo Challenges whose realm did
  not match the HTTP host unless the realm was trusted. This release follows mppx and has no
  such check.
- **`Receipt.payer`.** The payer is on `PaymentSucceeded.payer` and `Validation.payer`.
- **`paid_retry_timeout`.** `fetch()` applies no timeout unless you pass `timeout=`.
- **pympp 0.15 store keys.** Tempo replay claims and sponsored-submission recovery records use
  mppx's keys (`mppx:charge:<hash>`, `mppx:charge:recovery:<hash>`) instead of 0.15's
  `mpp:charge:…` and `mpp:charge-broadcast:…`. A store shared with 0.15 servers doesn't
  see their claims, and outstanding 0.15 recovery records are not reconciled. Drain payment
  traffic before switching.
- **Smaller removals:** `ChallengeEcho`, `Receipt.success()`, the `parse_*`/`format_*` free
  functions, `ParseError`, `VerificationError`, `Mpp(defaults=…)`, module-level
  `get/post/request`, `PaymentEventName`, `MemoryStore(max_entries=…)`, `put_if_absent`,
  `ExpiringStore`, `MCPChallenge`/`MCPCredential`/`MCPReceipt`, `TempoAccount.from_env`, the
  `stripe()` alias, `FEE_PAYER_VALID_BEFORE_SECS`, `get_transfers`, and the `server`/`sqlite`/`stripe` extras.

## Behavioural changes

- **Amount units.** Route amounts are decimal display strings converted by the method's request
  model (Tempo 6 decimals, Stripe as configured). pympp's standalone `pay` /
  `verify_or_challenge` and the MCP `pay` decorator took **base units**. Here every transport
  goes through the same method schema, so MCP and standalone flows also take display units
  (`"0.01"`, not `"10000"`).
- **Currency offers.** Both releases offer OUSD first, then USDC.e (mainnet) or pathUSD
  (Moderato). pympp hid this inside one method. Here `tempo.charge()` returns one `ServerMethod`
  per currency and `mpp.charge(...)` composes them. Use `tempo.charge(currencies=[...])` to
  change the list.
- **Default chain.** Mainnet (4217) in both. `testnet=True` or `chain_id=42431` selects
  Moderato.
- **Realm detection.** Both read `MPP_REALM` and the platform variables and ignore
  `HOST`/`HOSTNAME`. pympp then fell back to `"localhost"`. This release uses the **request's
  hostname**, then `"MPP Payment"`. Set `MPP_REALM` or `realm=` behind a proxy that rewrites
  `Host`.
- **Secret key.** Still read from `MPP_SECRET_KEY` and never generated, but keys shorter than
  32 bytes raise `ValueError`. Generate one with `openssl rand -base64 32`.
- **Route binding.** pympp 0.15 bound the HTTP method, route, path and query under
  `_mppx_scope`. This release binds `"METHOD /route/template"` through the Challenge's
  `opaque` metadata, as mppx does: the query string is not bound. Override it with `scope=`.
  Credentials for Challenges issued by 0.15 are rejected and the client receives a fresh 402,
  so drain payment traffic or pin issuance and retries to one version during the switch.
- **Errors from hooks.** Exceptions that are not `PaymentError`s become a generic 500 problem.
- **Replay stores.** See [Stores](#stores). Zero-amount proof Credentials are replay-protected
  only when you pass an explicit store (mppx behaviour).
- **Client redirects.** `fetch()` and `mpp.client()` follow redirects **before** payment, like
  `fetch`. A redirect that answers a paid request is returned unfollowed, and the Credential is
  never re-sent.
- **Client timeouts.** `fetch()` applies no timeout unless you pass `timeout=`. `mpp.client()`
  keeps httpx's default unless you pass `timeout=`.
- **Paid-retry outcomes.** As in 0.15, a paid request that fails or is cancelled after the
  Credential was sent emits `payment.failed` with `PaymentOutcomeUnknownError`, and a 5xx answer
  is returned as-is without paying again.
- **Concurrency.** Everything is `async`. There is no sync client. Hooks may be sync or async.
