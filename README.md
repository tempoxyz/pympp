# pympp

Python SDK for the [**Machine Payments Protocol**](https://mpp.dev)

[![PyPI](https://img.shields.io/pypi/v/pympp.svg)](https://pypi.org/project/pympp/)
[![License](https://img.shields.io/pypi/l/pympp.svg)](LICENSE)

## Documentation

Full documentation, API reference, and guides are available at **[mpp.dev/sdk/python](https://mpp.dev/sdk/python)**.

## Install

```bash
pip install pympp
```

## Quick Start

### Server

```python
from mpp import Credential, Receipt
from mpp.server import Mpp, pay
from mpp.methods.tempo import server as tempo

server = Mpp(methods=tempo.charge(recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"))


@app.get("/paid")
@pay(server.charge(amount="0.50"))
async def handler(request, credential: Credential, receipt: Receipt):
    return JSONResponse({"data": "...", "payer": receipt.payer})
```

Without a framework decorator, call the route handler with the framework-neutral
`Request`. It returns `PaymentRequired` (a `402` response to send as-is) or
`PaymentVerified`:

```python
from mpp.server import Request, Response


async def handle(request: Request) -> Response:
    result = await server.charge(amount="0.50")(request)
    if result.status != 200:
        return result.challenge
    if result.response is not None:
        return result.response  # the method handled it, such as a session top-up or close
    return result.with_receipt(Response.json({"data": "..."}))
```

A `tempo.charge(fee_payer=...)` server sponsors its payers' fees on every route, as
mppx does; pass `fee_payer=False` to a route to opt out. Before broadcasting a
sponsored charge it simulates it with `eth_call`, which every public Tempo RPC serves.

If the endpoint already uses `Authorization` (API keys, Bearer tokens), create the server with `requires_auth=True`. Challenges then advertise `header="Payment-Authorization"`, and clients send the Payment credential in that header instead of `Authorization`.

```python
server = Mpp(methods=tempo.charge(recipient="0x..."), requires_auth=True)
```

### Serve x402 clients

The `evm` method charges with EIP-3009 authorizations (USDC on Base and other
EVM chains). It serves native MPP clients and x402 v2 `exact` clients from the
same endpoint: unpaid responses carry `PAYMENT-REQUIRED` next to
`WWW-Authenticate`, x402 clients pay with `PAYMENT-SIGNATURE`, and paid x402
responses carry `PAYMENT-RESPONSE`. An x402 facilitator settles payments.

```bash
pip install "pympp[evm]"
```

```python
from mpp.methods.evm import BASE_USDC
from mpp.methods.evm import server as evm
from mpp.server import Mpp

server = Mpp(
    methods=evm.charge(
        currency=BASE_USDC,
        recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        facilitator="https://facilitator.example.com",
    ),
)


@app.get("/paid")
@pay(server.charge(amount="0.01"))
async def handler(request, credential, receipt):
    return JSONResponse({"data": "..."})
```

To settle on Base mainnet through Coinbase's facilitator, install the `cdp` extra
and pass `mpp.x402.cdp.facilitator()`. It reads `CDP_API_KEY_ID` and
`CDP_API_KEY_SECRET` and signs a JWT for each request, as `@coinbase/x402` does.
Other facilitators that need per-endpoint auth take
`HttpFacilitator(url, create_auth_headers=...)`.

```python
from mpp.x402 import cdp

method = evm.charge(currency=BASE_USDC, recipient="0x...", facilitator=cdp.facilitator())
```

Routes bind x402 payments the way mppx does. Routes are scoped to their HTTP
method, path and query, and with the default `route_binding="required"` they only
accept clients that sign mppx's `extensions.mppx` route binding. To accept
standard x402 clients there, such as Coinbase's SDK, pass
`route_binding="resource"` to `evm.charge()`; they're then bound by the echoed terms and
resource URL.

Return a response object so pympp can add `PAYMENT-RESPONSE`. Pass
`methods=[tempo.charge(...), evm.charge(...)]` to offer both on one route. The `402` response of
a route handler already carries `PAYMENT-REQUIRED`. Send paid responses with
`Cache-Control: private` so shared caches can't serve them to callers who didn't
pay. `with_receipt()` adds it, and `PAYMENT-RESPONSE`, when the handler returns a
response object rather than plain data.

### Client

```python
from mpp.client import Mpp
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo

account = TempoAccount.from_key("0x...")

async with Mpp(methods=[tempo.charge(account=account)]) as mpp:
    response = await mpp.fetch("https://mpp.dev/api/ping/paid")
```

To use your own `httpx.AsyncClient`, pass it `transport=mpp.payment_transport`, or
call `mpp.client()`.

### Pay x402 servers

The `evm` client method also pays x402 v2 `exact` servers (EIP-3009 USDC),
such as ones built with Coinbase's x402 SDK, as mppx's client does. On a `402`
carrying `PAYMENT-REQUIRED`, the client picks an offer in its currency and chain
within `max_amount`, signs it and retries with `PAYMENT-SIGNATURE`. When a
server offers both an MPP challenge the client can pay and x402, it pays MPP.

```python
from mpp.client import Mpp
from mpp.methods.evm import BASE_USDC
from mpp.methods.evm import client as evm
from mpp.x402 import payment_response

method = evm.charge(currency=BASE_USDC, account=account, max_amount="0.01")
async with Mpp(methods=[method]) as mpp:
    response = await mpp.fetch("https://api.example.com/x402/paid")
    receipt = payment_response(response)  # PAYMENT-RESPONSE: transaction, payer, network
```

Permit2 offers are not paid.

Custom transports can reuse method matching and credential creation without
depending on HTTPX:

```python
from mpp.client import PaymentTransport
from mpp.runtime import PaymentRuntime

payments = PaymentRuntime([method])
challenge, method = payments.match_challenge(challenges)
credential = await payments.create_credential(challenge, method)

transport = PaymentTransport(runtime=payments)
```

## Examples

Stripe charges verify Shared Payment Tokens:

```python
from mpp.methods.stripe import server as stripe

server = Mpp(methods=stripe.charge(secret_key="sk_...", network_id="bn_...", currency="usd"))
```

Stripe charge and composed-offer inputs accept `payment_intent_options` as a
mapping or a sync/async callable receiving `PaymentIntentContext`. The supported
fields are `customer`, `receipt_email`, `metadata`, and
`hooks.inputs.tax.calculation`. The input stays out of the signed challenge.
Resolvers run in the terminal payment operation, after available credential
validation; `validate_credential()` never invokes them.

```python
async def options(context):
    return {"metadata": {"order_id": "order_123"}}


handler = server.charge(amount="0.50", payment_intent_options=options)
# Also supported in compose offer mappings.
```

Both Stripe rails include SDK/challenge analytics. Existing configured metadata
retains its precedence, including the forced `machine_payment="true"` flag;
the new options' metadata overrides all generated/configured metadata. Crypto
recording retries a definitive optional-field rejection once without optional
fields, and remains best-effort after settlement.

Custom methods define a `mpp.methods.Method` (wire name, intent and pydantic
request and payload models) and wrap it in a `mpp.server.ServerMethod` (`verify`,
or `validate` and `broadcast` hooks) or a `mpp.client.ClientMethod`
(`create_credential`). A request model may consume private route input, such as
`payment_intent_options`, by leaving it out of the wire request.

| Example | Description |
|---------|-------------|
| [api-server](./examples/api-server/) | Payment-gated API server |
| [fetch](./examples/fetch/) | CLI tool for fetching URLs with automatic payment handling |
| [mcp-server](./examples/mcp-server/) | MCP server with payment-protected tools |
| [x402-client](./examples/x402-client/) | pympp client paying an official x402 server |
| [session-metered-api](./examples/session-metered-api/) | Sub-cent metered API and an agent paying 500 calls through one session (Docker Compose) |

## Protocol

Built on the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ryan-httpauth-payment/). See [mpp-specs](https://tempoxyz.github.io/mpp-specs/) for the full specification.

## License

MIT OR Apache-2.0

### Restrict automatic payment origins

When fetching URLs from untrusted sources, configure exact origins before enabling
payments. Origins include the scheme and port; paths and credentials are rejected.
An empty allowlist disables automatic payments. Omitting it preserves the default
of allowing payments to any directly requested origin.

```python
async with Mpp(
    methods=[tempo.charge(account=account)],
    allowed_origins=["https://api.example.com"],
) as mpp:
    response = await mpp.fetch("https://api.example.com/paid")
```

Use method-level amount, currency, and recipient limits as well. A challenge realm
is a protection-space name, not an authenticated origin. This policy prevents
payments to unapproved origins; it cannot identify a relayed challenge served by
an origin you have already approved.

### External fee-payer services

An external `feePayerUrl` signs sponsored transactions through `eth_signRawTransaction`.
Treat the returned transaction as a spending capability: callers can broadcast it
without passing through pympp. Before returning a signature, the service must
validate the complete transaction and caller authorization, simulate execution,
and enforce gas-price, gas-limit, per-caller, and aggregate spending budgets.
Simulation is a point-in-time check; state can change before inclusion, so it does
not replace hard spending limits.

These requirements apply to any external sponsor. pympp validates the expected
payment before requesting sponsorship, but its checks cannot protect a sponsor
that also accepts direct signing requests. Local sponsorship uses pympp's local
simulation path; externally signed transactions rely on the external service's
pre-sign controls. Adding a simulation after receiving the signature would not
prevent a caller from broadcasting that same transaction elsewhere.

### Sponsored recovery records

Sponsored charge recovery records now retain the original signed transaction.
Legacy records containing only a fee-token address can recover confirmed
receipts while the original sponsor key is available. A missing receipt for a
reconstructed transaction is not proof that the original payment failed, so
these records remain non-payable until reconciled.

Before rotating sponsor keys, drain outstanding sponsored submissions. To
migrate a remaining legacy record, pause payment traffic and replace its value
under the existing `mpp:charge-broadcast:<client-envelope-hash>` key with the
original canonical signed `0x76` transaction from your submission log. Keep the
key unchanged and use the actual submitted bytes, not a transaction signed with
a replacement key. Resume traffic after the migration; retries will reconcile
the stored transaction. If the original bytes or key are unavailable, retain the
record for operator reconciliation rather than deleting an unknown payment.

Recovery records created by `MemoryStore`, `SQLiteStore`, and `RedisStore` expire
after both the authenticated challenge's expiry and the signed transaction's
`valid_before` plus the inclusion grace period. Retries do not extend this deadline, and a store-wide TTL does not shorten it. Replay reservations retain
their existing retention policy. Memory and SQLite reclaim abandoned expired
records during subsequent store activity; Redis expires them automatically.
Redis-backed sponsored recovery requires Redis 6.2 or later for atomic
[`SET NX PXAT`](https://redis.io/docs/latest/commands/set/) absolute expiry.
Custom stores can implement `mpp.store.ExpiringStore.put_if_absent_until(key,
value, expires_at)` with an atomic insert and absolute Unix timestamp to support
this cleanup. Stores without that method, and challenges without an expiry,
retain durable recovery records. Existing records keep their original retention.

### Payment request context

Route handlers bind `meta` into their signed challenges:

```python
handler = server.charge(amount="1.00", meta={"account": authenticated_account_id})
```

Derive `authenticated_account_id` from trusted session authentication, not an
unverified request field. Route handlers also bind the HTTP method, path and
query, and the route template that framework decorators report. Configured `_mppx_scope` is preserved in full
under the signed scope’s `custom` key, alongside trusted framework fields.
Custom request objects should expose their HTTP `method`.

Server issuance adds random opaque `_mpp_nonce` metadata; this key is reserved.
Nonces prevent identical challenges across callers even with fixed expirations,
but do not authenticate a presenter who stole the entire credential. Low-level
`Challenge.create()` remains deterministic; custom issuance must provide its own
unique authenticated context. Nonce-free challenges remain valid when their
other bindings match. HTTP credentials lacking method scope or using the old custom-scope representation
will be rejected after upgrading. Keep credentials confidential and share an
atomic replay store across workers and replicas.

This release changes HTTP method scope, custom scope representation, and direct
metadata binding as well as nonce issuance. Dict request bodies are now digested
like mppx (`JSON.stringify` key order) instead of with sorted keys; verifiers
still accept the old sorted-key digest, but older verifiers reject new ones. Use an atomic rollout with payment
traffic drained, or pin challenge issuance and all credential retries to the
same version until outstanding challenges expire. Merely switching all replicas
at once can still strand payments already issued by the old version.

`unique_challenges=False` (`Mpp`) disables only nonce issuance; it does **not** make this
release compatible with old verifiers. It cannot disable the new method,
custom-scope, or metadata bindings. Mixing versions can reject already settled
hash payments and cause a client to pay again. Nonce-only staging is useful only
when all other challenge bindings already match; it temporarily retains the
fixed-expiry collision risk. Shared application authentication is still required.

Fixed Tempo split memos must not use the MPP attribution format: such a transfer
can otherwise also pay the challenge named by its memo. Omit a split's memo to
let the client bind it to the current challenge, or use an application memo
outside the MPP format. Servers reject this configuration before issuing a
challenge, and clients reject it before signing or broadcasting. Drain or
replace outstanding challenges with fixed MPP memos before upgrading; their
transfers cannot safely authorize the enclosing split charge.
