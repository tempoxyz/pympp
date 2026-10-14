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
    return {"data": "...", "payer": credential.payer}
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
