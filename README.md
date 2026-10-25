# pympp

Python SDK for the [Machine Payments Protocol](https://mpp.dev): the `Payment` HTTP
authentication scheme for HTTP 402.

pympp follows the engine model and behaviour of the TypeScript reference SDK
[mppx](https://github.com/wevm/mppx).

- Server: protect any route with one or more payment offers. It works with any framework and
  ships a Starlette/FastAPI decorator.
- Client: an `httpx` transport that pays 402 Challenges automatically.
- Payment methods: Tempo charge, Stripe charge (Shared Payment Tokens, machine payments), and
  generic EVM charge (EIP-3009) that also serves x402 clients.
- MCP: paid tools and a paying client on the official MCP Python SDK.

## Install

Requires **Python ≥ 3.12**. The distribution is named `pympp` and the import package is `mpp`.

```bash
pip install "pympp[tempo]"          # core + Tempo
pip install "pympp[tempo,asgi]"     # + Starlette/FastAPI integration
uv add "pympp[tempo]"
```

| Extra | Installs | Enables |
|---|---|---|
| *(none)* | `httpx`, `pydantic` | `mpp`, `mpp.server`, `mpp.client`, `mpp.store`, `mpp.stripe`, `mpp.x402` wire types and client protocol |
| `tempo` | `pytempo`, `eth-account`, `eth-abi`, `rlp`, `cryptography` | `mpp.tempo` (charge) |
| `evm` | `eth-account`, `eth-abi` | `mpp.evm` signing (EIP-3009 charge) |
| `asgi` | `starlette` | `mpp.server.starlette` (`@paid` for Starlette/FastAPI) |
| `redis` | `redis` | `mpp.store.redis(...)` (shared replay store) |
| `mcp` | `mcp>=2.3` | `mpp.mcp_sdk` (official MCP Python SDK integration) |

## Quick start: server

This example uses FastAPI with Tempo payments on the Moderato testnet. It needs
`pip install "pympp[tempo,asgi]" fastapi`.

```python
import os

from fastapi import FastAPI

from mpp.server import Mpp
from mpp.server.starlette import paid
from mpp.tempo import server as tempo

mpp = Mpp(
    methods=tempo.charge(recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00", testnet=True),
    secret_key=os.environ["MPP_SECRET_KEY"],  # >= 32 bytes: openssl rand -base64 32
)
app = FastAPI()


@app.get("/premium")
@paid(mpp.charge(amount="0.01"))
async def premium() -> dict[str, str]:
    return {"data": "paid content"}
```

- `tempo.charge(...)` returns one offer per accepted currency (OUSD, then pathUSD on Moderato
  or USDC.e on mainnet). `mpp.charge(...)` offers all of them on the route.
- Amounts are decimal strings in display units: `"0.01"` with 6 decimals goes on the wire as
  `10000`.
- A request without a Credential gets `402` plus `WWW-Authenticate: Payment …`. A paid request
  runs the endpoint, and the response carries `Payment-Receipt`.
- The realm defaults to `MPP_REALM` (or a platform host variable), then the request host.
- Replay protection uses an in-memory store by default, which only protects a single process.
  Production deployments with more than one worker need a shared store, for example
  `tempo.charge(..., store=mpp.store.redis(redis_client))`.

Without Starlette, call the handler with the framework-neutral types:

```python
from mpp.server import Request, Response


async def handle(request: Request) -> Response:
    result = await mpp.charge(amount="0.01")(request)
    if result.status == 402:
        return result.challenge  # 402 with WWW-Authenticate
    return result.with_receipt(Response.json({"data": "paid content"}))
```

## Quick start: client

```python
import asyncio
import os

from mpp.client import Mpp
from mpp.tempo import client as tempo
from mpp.tempo.client import secp256k1_account


async def main() -> None:
    account = secp256k1_account(os.environ["TEMPO_PRIVATE_KEY"])
    async with Mpp(methods=[tempo.charge(account=account)]) as mpp:
        response = await mpp.fetch("https://api.example.com/premium")
        print(response.status_code, response.json(), response.headers["payment-receipt"])


asyncio.run(main())
```

`mpp.fetch` retries 402 responses with a Credential. It applies no timeout unless you pass
`timeout=`, because paid requests may wait for settlement. To use your own client, plug
`mpp.payment_transport` into `httpx.AsyncClient(transport=...)`, or call `mpp.client()`.

## Development

```bash
uv sync --all-extras --dev
make check          # ruff + pyright + pytest
make conformance    # mpp-tools vectors, flows and server verification (needs node >= 22.18)
```

## License

MIT OR Apache-2.0
