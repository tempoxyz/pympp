# API Server Example

A FastAPI server with payment-protected endpoints using the Machine Payments Protocol.

## What This Demonstrates

- Free endpoints that anyone can access
- Paid endpoints protected by the `@pay` decorator
- Automatic 402 challenge/response flow for the Payment HTTP Authentication Scheme

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- [purl](https://purl.tempo.xyz/) for testing paid endpoints

## Installation

```bash
cd examples/api-server
uv sync
```

## Configuration

Set environment variables (optional - defaults are provided):

```bash
export TEMPO_RPC_URL="https://rpc.testnet.tempo.xyz/"
export PAYMENT_DESTINATION="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
```

## Running

```bash
uv run python server.py
```

The server starts at http://localhost:8000.

## Testing

**Free endpoint** (no payment required):

```bash
curl http://localhost:8000/free
# {"message":"This content is free!"}
```

**Paid endpoint** (use purl to handle payment automatically):

```bash
purl http://localhost:8000/paid
# {"message":"This is paid content!","payer":"0x...","tx":"0x..."}
```

**Paid endpoint without payment** (returns 402):

```bash
curl -i http://localhost:8000/paid
# HTTP/1.1 402 Payment Required
# WWW-Authenticate: Payment ...
```

## Code Walkthrough

### Payment Handler

```python
from mpp.server import Mpp
from mpp.methods.tempo import tempo

server = Mpp.create(
    method=tempo(currency=PATH_USD, recipient=DESTINATION),
)
```

`Mpp.create()` sets up the payment handler with smart defaults:
- **realm** auto-detected from environment (`MPP_REALM`, `VERCEL_URL`, etc.)
- **secret_key** auto-generated and persisted to `.env`
- **currency** and **recipient** configured once on the method

### Charging

```python
result = await server.charge(
    authorization=request.headers.get("Authorization"),
    amount="0.001",
)
```

- `amount` is in dollars (e.g., `"0.50"` = $0.50), auto-converted to base units
- `expires` defaults to now + 5 minutes
- No nested request dict needed

### Payment Flow

1. **No Authorization header**: Returns a `Challenge` → respond with 402
2. **Valid credential**: Returns `(Credential, Receipt)` → return the resource
3. **Invalid credential**: Returns a `Challenge` → respond with 402
