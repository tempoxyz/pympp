# pympp

Python SDK for the [**Machine Payments Protocol**](https://machinepayments.dev)

[![PyPI](https://img.shields.io/pypi/v/pympp.svg)](https://pypi.org/project/pympp/)
[![License](https://img.shields.io/pypi/l/pympp.svg)](LICENSE)

## Documentation

Full documentation, API reference, and guides are available at **[machinepayments.dev/sdk/python](https://machinepayments.dev/sdk/python)**.

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
        currency="0x20c0000000000000000000000000000000000000",
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
    response = await client.get("https://api.example.com/resource")
```

## Examples

| Example | Description |
|---------|-------------|
| [api-server](./examples/api-server/) | Payment-gated API server |
| [fetch](./examples/fetch/) | CLI tool for fetching URLs with automatic payment handling |
| [mcp-server](./examples/mcp-server/) | MCP server with payment-protected tools |

## Protocol

Built on the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ietf-httpauth-payment/). See [payment-auth-spec](https://github.com/tempoxyz/payment-auth-spec) for the full specification.

## License

MIT OR Apache-2.0
