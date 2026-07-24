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
async HTTP, and explicit MCP clients. HTTPX instrumentation makes existing and
future standard `httpx` clients payment-aware:

```python
import httpx

from mpp.instrumentation import instrument
from mpp.methods.tempo import ChargeIntent, TempoAccount, tempo
from mpp.runtime import PaymentRuntime


def method_factory():
    return tempo(
        account=TempoAccount.from_key("0x..."),
        intents={"charge": ChargeIntent()},
    )


with PaymentRuntime(
    method_factories=[method_factory],
    allowed_origins=["https://api.example.com"],
) as runtime:
    with instrument(runtime):
        response = httpx.get("https://api.example.com/paid")
```

MCP stays explicit. Inside the same runtime's lifetime, inject it into
`McpClient`:

```python
from mpp.extensions.mcp import McpClient

async with PaymentRuntime(
    method_factories=[method_factory],
    allowed_origins=["https://api.example.com"],
) as runtime:
    async with McpClient(session, runtime=runtime) as mcp:
        result = await mcp.call_tool("premium_tool", {"query": "hello"})
```

`PaymentRuntime` owns one event loop. Factories construct loop-bound methods on
that loop and async context-manager results are closed there. Direct `methods`
are borrowed and must be loop-independent.

For one client instead of patching the standard client classes, use
`runtime.wrap_client(client)` or `runtime.wrap_async_client(client)`.
Instrumentation is context-scoped by default. Single-wallet plugins whose calls
run on independent worker threads can opt in to process scope with
`instrument(runtime, scope="process")`.
Global instrumentation requires `allowed_origins`; use
`allow_unrestricted=True` only when the runtime should be able to pay any
origin.

The monkey-patching adapters—global instrumentation, `wrap_client`, and
`wrap_async_client`—support HTTPX `0.27.x` and `0.28.x`. They validate the
installed adapter before patching and fail without changing HTTPX when the
version or adapter shape is unsupported. Explicit `PaymentTransport` and
`SyncPaymentTransport` remain available without the private HTTPX adapter seam.

After a credential is sent, failures or a repeated payment challenge mark its
outcome unknown; matching future payment attempts raise
`PaymentOutcomeUnknownError` and remain blocked on that runtime to prevent
accidental repayment. Global and per-client adapters include redirects,
response hooks, and body consumption in that outcome boundary. Use a stable,
unique `Idempotency-Key` for each logical HTTP operation so retries can be
matched reliably. Each protocol retains at most `max_unknown_outcomes`
tombstones (1,024 by default). Reaching that limit blocks all new payments for
the protocol instead of evicting safety state. After externally reconciling
every unknown outcome, reopen payments explicitly with
`runtime.reset_unknown_outcomes(reconciled=True)`.

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
