# FastAPI Server

Payment-protected endpoints with FastAPI.

## Dependencies

```toml
[project]
dependencies = [
    "mpay[tempo,server]",
    "fastapi",
    "uvicorn",
]
```

## Basic Decorator

The `@requires_payment` decorator handles the 402 flow automatically:

```python
from fastapi import FastAPI, Request
from mpay import Credential, Receipt
from mpay.server import requires_payment
from mpay.methods.tempo import ChargeIntent

app = FastAPI()
intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

@app.get("/resource")
@requires_payment(
    intent=intent,
    request={
        "amount": "1000",
        "asset": "0x20c0000000000000000000000000000000000001",
        "destination": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
    },
    realm="api.example.com",
)
async def get_resource(request: Request, credential: Credential, receipt: Receipt):
    return {"data": "paid content", "payer": credential.source}
```

## Dynamic Pricing

Use a callable for dynamic request parameters:

```python
@app.get("/dynamic")
@requires_payment(
    intent=intent,
    request=lambda req: {
        "amount": req.query_params.get("price", "1000"),
        "asset": "0x20c0000000000000000000000000000000000001",
        "destination": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
    },
    realm="api.example.com",
)
async def dynamic_pricing(request: Request, credential: Credential, receipt: Receipt):
    return {"data": "..."}
```

## Manual Flow

For more control, use `verify_or_challenge` directly:

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mpay import Challenge
from mpay.server import verify_or_challenge
from mpay.methods.tempo import ChargeIntent

app = FastAPI()
intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

@app.get("/manual")
async def manual_payment(request: Request):
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
            status_code=402,
            headers={"WWW-Authenticate": result.to_www_authenticate("api.example.com")},
            content={"error": "Payment Required"},
        )

    credential, receipt = result
    return JSONResponse(
        content={"data": "paid content"},
        headers={"Payment-Receipt": receipt.to_payment_receipt()},
    )
```

## Full Application

```python
from fastapi import FastAPI, Request
from mpay import Credential, Receipt
from mpay.server import requires_payment
from mpay.methods.tempo import ChargeIntent

app = FastAPI()
intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

PAYMENT_REQUEST = {
    "amount": "1000",
    "asset": "0x20c0000000000000000000000000000000000001",
    "destination": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
}

@app.get("/free")
async def free_endpoint():
    return {"message": "This is free"}

@app.get("/paid")
@requires_payment(intent=intent, request=PAYMENT_REQUEST, realm="api.example.com")
async def paid_endpoint(request: Request, credential: Credential, receipt: Receipt):
    return {
        "message": "This is paid content",
        "payer": credential.source,
        "tx": receipt.reference,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```
