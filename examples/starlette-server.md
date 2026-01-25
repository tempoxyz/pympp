# Starlette Server

Payment-protected endpoints with Starlette.

## Dependencies

```toml
[project]
dependencies = [
    "mpay[tempo,server]",
    "starlette",
    "uvicorn",
]
```

## Basic Usage

```python
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from mpay import Challenge, Credential, Receipt
from mpay.server import verify_or_challenge
from mpay.methods.tempo import ChargeIntent

intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

async def paid_resource(request: Request):
    result = await verify_or_challenge(
        authorization=request.headers.get("Authorization"),
        intent=intent,
        request={
            "amount": "1000",
            "asset": "0x20c0000000000000000000000000000000000001",
            "destination": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
        },
        realm="api.example.com",
    )

    if isinstance(result, Challenge):
        return JSONResponse(
            {"error": "Payment Required"},
            status_code=402,
            headers={"WWW-Authenticate": result.to_www_authenticate("api.example.com")},
        )

    credential, receipt = result
    return JSONResponse(
        {"data": "paid content", "payer": credential.source},
        headers={"Payment-Receipt": receipt.to_payment_receipt()},
    )

app = Starlette(routes=[
    Route("/resource", paid_resource),
])
```

## With Decorator

The `@requires_payment` decorator also works with Starlette:

```python
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from mpay import Credential, Receipt
from mpay.server import requires_payment
from mpay.methods.tempo import ChargeIntent

intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

@requires_payment(
    intent=intent,
    request={
        "amount": "1000",
        "asset": "0x20c0000000000000000000000000000000000001",
        "destination": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
    },
    realm="api.example.com",
)
async def paid_resource(request: Request, credential: Credential, receipt: Receipt):
    return JSONResponse({"data": "paid content", "payer": credential.source})

app = Starlette(routes=[
    Route("/resource", paid_resource),
])
```
