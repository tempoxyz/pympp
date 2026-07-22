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

### Shared runtime

Use one runtime to share payment methods, policy, and events across sync HTTP,
async HTTP, and MCP. Instrumentation makes existing and future standard
`httpx` clients and MCP `ClientSession.call_tool` calls payment-aware:

```python
import httpx

from mpp.instrumentation import instrument
from mpp.methods.tempo import ChargeIntent, TempoAccount, tempo
from mpp.runtime import PaymentRuntime

method = tempo(
    account=TempoAccount.from_key("0x..."),
    intents={"charge": ChargeIntent()},
)
runtime = PaymentRuntime([method], allowed_origins=["https://api.example.com"])

try:
    with instrument(runtime):
        response = httpx.get("https://api.example.com/paid")
finally:
    runtime.close()
```

For one client instead of process-scoped instrumentation, use
`runtime.wrap_client(client)` or `runtime.wrap_async_client(client)`.

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
