# API Server Example

A FastAPI server with payment-protected endpoints using the Machine Payments Protocol.

## What This Demonstrates

- Free endpoints that anyone can access
- Paid endpoints protected by the `@pay` decorator
- Automatic 402 challenge/response flow for the Payment HTTP Authentication Scheme

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Installation

```bash
cd examples/api-server
uv sync
```

## Configuration

Set the secret that signs challenges, and optionally the recipient and a fee payer:

```bash
export MPP_SECRET_KEY="$(openssl rand -hex 32)"
export PAYMENT_DESTINATION="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
export FEE_PAYER_KEY="0x..."  # optional: sponsor clients' gas
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

**Paid endpoint** (use the [fetch example](../fetch/) to pay automatically):

```bash
python ../fetch/fetch.py --key 0x... --rpc-url https://rpc.moderato.tempo.xyz http://localhost:8000/paid
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
from mpp.methods.tempo import server as tempo

server = Mpp(methods=tempo.charge(currency=PATH_USD, recipient=DESTINATION))
```

`Mpp` sets up the payment handler with smart defaults:
- **realm** auto-detected from environment (`MPP_REALM`, `VERCEL_URL`, etc.)
- **secret_key** read from `MPP_SECRET_KEY` env var (or passed explicitly)
- **currency** and **recipient** configured once on the method

### Charging

```python
handler = server.charge(amount="0.001")
result = await handler(PaymentRequest(request.method, str(request.url), headers=dict(request.headers)))
```

- `amount` is in dollars (e.g., `"0.50"` = $0.50), auto-converted to base units
- `expires` defaults to now + 5 minutes
- No nested request dict needed

### Payment Flow

1. **No Authorization header**: Returns `PaymentRequired` → respond with its `402` `challenge`
2. **Valid credential**: Returns `PaymentVerified` → return the resource with `with_receipt()`
3. **Invalid credential**: Returns `PaymentRequired` → respond with its `challenge`
