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
    return {"data": "...", "payer": credential.source}
```

### Client

```python
from mpp.client import Client
from mpp.methods.tempo import tempo, TempoAccount, ChargeIntent

account = TempoAccount.from_key("0x...")

async with Client(methods=[tempo(account=account, intents={"charge": ChargeIntent()})]) as client:
    response = await client.get("https://mpp.dev/api/ping/paid")
```

Custom integrations can share method matching, events, and credential creation:

```python
from mpp.runtime import PaymentRuntime

async with PaymentRuntime([method]) as runtime:
    challenge, method = runtime.match_challenge(challenges)
    credential = await runtime.create_credential(challenge, method)
```

The runtime borrows its methods and runs them on the caller's event loop.

The same runtime can power asynchronous HTTP clients while limiting which
origins may receive payment credentials:

```python
async with PaymentRuntime(
    [method],
    allowed_origins=["https://api.example.com"],
) as runtime:
    async with Client(runtime=runtime) as client:
        response = await client.get("https://api.example.com/paid")
```

If a credential is sent but its outcome cannot be confirmed, matching attempts
raise `mpp.errors.PaymentOutcomeUnknownError`. Reconcile them externally before
calling `runtime.reset_unknown_outcomes(reconciled=True)`.

## Examples

| Example | Description |
|---------|-------------|
| [api-server](./examples/api-server/) | Payment-gated API server |
| [fetch](./examples/fetch/) | CLI tool for fetching URLs with automatic payment handling |
| [mcp-server](./examples/mcp-server/) | MCP server with payment-protected tools |

## Protocol

Built on the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ryan-httpauth-payment/). See [mpp-specs](https://tempoxyz.github.io/mpp-specs/) for the full specification.

## License

MIT OR Apache-2.0
