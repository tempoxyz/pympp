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
from mpp.server import Mpp
from mpp.methods.tempo import tempo, ChargeIntent

server = Mpp.create(
    method=tempo(
        intents={"charge": ChargeIntent()},
        recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
    ),
)


@app.get("/paid")
@server.pay(amount="0.50")
async def handler(request, credential: Credential, receipt: Receipt):
    return {"data": "...", "payer": receipt.payer}
```

If the endpoint already uses `Authorization` (API keys, Bearer tokens), create the server with `requires_auth=True`. Challenges then advertise `header="Payment-Authorization"`, and clients send the Payment credential in that header instead of `Authorization`.

```python
server = Mpp.create(method=tempo(...), requires_auth=True)

result = await server.charge(
    authorization=request.headers.get("Authorization"),
    amount="0.50",
    payment_authorization=request.headers.get("Payment-Authorization"),
)
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
from mpp.methods.evm import BASE_USDC, evm
from mpp.server import Mpp

server = Mpp.create(
    method=evm(
        currency=BASE_USDC,
        recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        facilitator="https://facilitator.example.com",
    ),
)


@app.get("/paid")
@server.pay(amount="0.01")
async def handler(request, credential, receipt):
    return JSONResponse({"data": "..."})
```

Return a response object so pympp can add `PAYMENT-RESPONSE`. Pass
`methods=[tempo(...), evm(...)]` to offer both on one route. Servers that build
responses themselves pass `payment_signature=` and `resource_url=` to
`server.charge()` and add `server.x402_payment_required(result, url)` to 402s.

### Client

```python
from mpp.client import Client
from mpp.methods.tempo import tempo, TempoAccount, ChargeIntent

account = TempoAccount.from_key("0x...")

async with Client(methods=[tempo(account=account, intents={"charge": ChargeIntent()})]) as client:
    response = await client.get("https://mpp.dev/api/ping/paid")
```

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

Stripe charge and composed-offer inputs accept `payment_intent_options` as a
mapping or a sync/async callable receiving `PaymentIntentContext`. The supported
fields are `customer`, `receipt_email`, `metadata`, and
`hooks.inputs.tax.calculation`. The input stays out of the signed challenge.
Resolvers run in the terminal payment operation, after available credential
validation; `validate_credential()` never invokes them.

```python
async def options(context):
    return {"metadata": {"order_id": "order_123"}}


result = await server.charge(
    authorization,
    "0.50",
    payment_intent_options=options,
)
# Also supported in compose offer mappings and server.pay(...).
```

Both Stripe rails include SDK/challenge analytics. Existing configured metadata
retains its precedence, including the forced `machine_payment="true"` flag;
the new options' metadata overrides all generated/configured metadata. Crypto
recording retries a definitive optional-field rejection once without optional
fields, and remains best-effort after settlement.

Custom methods may implement the optional
`prepare_intent(intent, input) -> (intent, request_input)` hook to consume private
method-specific input before request construction. Return an isolated intent
view; never mutate a shared intent or execute deferred work during preparation.
Unconsumed unknown offer options are still rejected. Existing methods need no
changes, and the intent verification signatures and event payloads are unchanged.

| Example | Description |
|---------|-------------|
| [api-server](./examples/api-server/) | Payment-gated API server |
| [fetch](./examples/fetch/) | CLI tool for fetching URLs with automatic payment handling |
| [mcp-server](./examples/mcp-server/) | MCP server with payment-protected tools |

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
async with Client(
    methods=[tempo(account=account, intents={"charge": ChargeIntent()})],
    allowed_origins=["https://api.example.com"],
) as client:
    response = await client.get("https://api.example.com/paid")
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

### Payment request context

Direct and composed payment gates bind `meta` into their signed challenges:

```python
result = await payment.charge(authorization, "1.00", meta={"account": authenticated_account_id})
```

Derive `authenticated_account_id` from trusted session authentication, not an
unverified request field. Framework decorators also bind the HTTP method and
actual route, path, and query. Configured `_mppx_scope` is preserved in full
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

`unique_challenges=False` (`Mpp.create`, standalone `pay`, or
`verify_or_challenge`) disables only nonce issuance; it does **not** make this
release compatible with old verifiers. It cannot disable the new method,
custom-scope, or metadata bindings. Mixing versions can reject already settled
hash payments and cause a client to pay again. Nonce-only staging is useful only
when all other challenge bindings already match; it temporarily retains the
fixed-expiry collision risk. Shared application authentication is still required.
