# API Server Example

A FastAPI server with payment-protected endpoints using mpay.

## What This Demonstrates

- Free endpoints that anyone can access
- Paid endpoints protected by the `@requires_payment` decorator
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

### Payment Intent

```python
intent = ChargeIntent(rpc_url=RPC_URL)
```

The `ChargeIntent` handles payment verification. When a client submits a credential, the intent verifies the payment transaction on-chain.

### Payment Request

```python
PAYMENT_REQUEST = {
    "amount": "1000",
    "asset": "0x20c0000000000000000000000000000000000001",
    "destination": DESTINATION,
}
```

This defines what payment is required:
- `amount`: Payment amount in the asset's smallest unit
- `asset`: The TIP-20 token address (alphaUSD on Tempo testnet)
- `destination`: Address that receives the payment

### The `@requires_payment` Decorator

```python
@app.get("/paid")
@requires_payment(intent=intent, request=PAYMENT_REQUEST, realm="localhost:8000")
async def paid_endpoint(request: Request, credential: Credential, receipt: Receipt):
    ...
```

The decorator handles the full payment flow:

1. **No Authorization header**: Returns 402 with `WWW-Authenticate` challenge
2. **Valid credential**: Verifies payment, injects `credential` and `receipt` into handler
3. **Invalid credential**: Returns 402 with new challenge

### Handler Parameters

After successful payment verification, your handler receives:

- `request`: The original FastAPI Request object
- `credential`: Contains `source` (payer's DID) and payment proof
- `receipt`: Contains `reference` (transaction hash) and `timestamp`

## Payment Flow

```
Client                          Server
  |                               |
  |  GET /paid                    |
  |------------------------------>|
  |                               |
  |  402 + WWW-Authenticate       |
  |<------------------------------|
  |                               |
  |  [executes payment on-chain]  |
  |                               |
  |  GET /paid + Authorization    |
  |------------------------------>|
  |                               |
  |  [verifies payment]           |
  |                               |
  |  200 + Payment-Receipt        |
  |<------------------------------|
```
