# mpay-python

Python SDK for the Machine Payments Protocol (MPP) - an implementation of the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ietf-httpauth-payment/).

## Design Principles

- **Protocol-first** — Core types (`Challenge`, `Credential`, `Receipt`) map directly to HTTP headers
- **Async-native** — Built on httpx for modern async Python
- **Pluggable methods** — Payment networks (Tempo, Stripe, Ethereum) are independently packaged
- **Minimal dependencies** — Core has no dependencies; extras add what you need
- **Designed for extension** — `Method` and `Intent` are `typing.Protocol` definitions. Bring your own classes or functions—if they match the interface, they work. No base classes, no registration.

## Quick Start

### Server

```python
from mpay import Challenge
from mpay.server import verify_or_challenge
from mpay.methods.tempo import ChargeIntent

intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

async def handler(request):
    result = await verify_or_challenge(
        authorization=request.headers.get("Authorization"),
        intent=intent,
        request={
            "amount": "1000000",
            "asset": "0x20c0000000000000000000000000000000000001",
            "destination": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            "expires": "2030-01-20T12:00:00Z",
        },
        realm="api.example.com",
    )

    if isinstance(result, Challenge):
        return Response(
            status=402,
            headers={"WWW-Authenticate": result.to_www_authenticate("api.example.com")},
        )

    credential, receipt = result
    return Response(
        {"data": "..."},
        headers={"Payment-Receipt": receipt.to_payment_receipt()},
    )
```

### Client

#### Automatic: Client Wrapper

```python
from mpay.client import Client
from mpay.methods.tempo import tempo, TempoAccount

account = TempoAccount.from_key("0x...")

async with Client(methods=[tempo(account=account, rpc_url="https://rpc.tempo.xyz")]) as client:
    r1 = await client.get("https://api.example.com/a")
    r2 = await client.get("https://api.example.com/b")
```

#### Automatic: One-liner

```python
from mpay.client import get
from mpay.methods.tempo import tempo, TempoAccount

account = TempoAccount.from_key("0x...")

response = await get(
    "https://api.example.com/resource",
    methods=[tempo(account=account, rpc_url="https://rpc.tempo.xyz")],
)
```

#### Automatic: Custom httpx Transport

```python
from mpay.client import PaymentTransport
import httpx

transport = PaymentTransport(
    methods=[tempo(...)],
    inner=httpx.AsyncHTTPTransport(),
)

async with httpx.AsyncClient(transport=transport) as client:
    response = await client.get("https://api.example.com/resource")
```

#### Manual

```python
from mpay import Challenge, Credential
from mpay.methods.tempo import tempo, TempoAccount
import httpx

account = TempoAccount.from_key("0x...")
method = tempo(account=account, rpc_url="https://rpc.tempo.xyz")

async with httpx.AsyncClient() as client:
    res = await client.get("https://api.example.com/resource")
    if res.status_code != 402:
        return

    challenge = Challenge.from_www_authenticate(res.headers["www-authenticate"])
    credential = await method.create_credential(challenge)

    res2 = await client.get(
        "https://api.example.com/resource",
        headers={"Authorization": credential.to_authorization()},
    )
```

## API Reference

### Core

#### `Challenge`

A parsed payment challenge from a `WWW-Authenticate` header.

```python
from mpay import Challenge

challenge = Challenge(
    id="challenge-id",
    method="tempo",
    intent="charge",
    request={"amount": "1000000", "asset": "0x...", "destination": "0x..."},
)

header = challenge.to_www_authenticate("api.example.com")
parsed = Challenge.from_www_authenticate(header)
```

#### `Credential`

The credential passed to the `verify` function.

```python
from mpay import Credential

credential = Credential(
    id="challenge-id",
    payload={"hash": "0x..."},
    source="did:pkh:eip155:1:0x...",
)

header = credential.to_authorization()
parsed = Credential.from_authorization(header)
```

#### `Receipt`

Payment receipt returned after successful verification.

```python
from mpay import Receipt

receipt = Receipt(
    status="success",
    timestamp="2024-01-20T12:00:00Z",
    reference="0x...",
)

header = receipt.to_payment_receipt()
parsed = Receipt.from_payment_receipt(header)
```

### Server

#### `@requires_payment` Decorator

Simplifies payment-protected endpoints by handling the 402 challenge flow automatically:

```python
from mpay.server import requires_payment
from mpay.methods.tempo import ChargeIntent

intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")

@app.get("/resource")
@requires_payment(
    intent=intent,
    request={"amount": "1000", "asset": "0x...", "destination": "0x..."},
    realm="api.example.com",
)
async def get_resource(request: Request, credential: Credential, receipt: Receipt):
    return {"data": "paid content", "payer": credential.source}
```

With dynamic request params:

```python
@requires_payment(
    intent=intent,
    request=lambda req: {"amount": req.query_params.get("price", "1000"), ...},
    realm="api.example.com",
)
async def dynamic_pricing(request: Request, credential: Credential, receipt: Receipt):
    return {"data": "..."}
```

The decorator:

- Extracts Authorization header from the request (supports Starlette/FastAPI and Django)
- Calls `verify_or_challenge` internally
- Returns 402 with `WWW-Authenticate` header if payment required
- Calls handler with `(request, credential, receipt)` if verified

#### `verify_or_challenge`

For more control, use `verify_or_challenge` directly:

```python
from mpay.server import verify_or_challenge

result = await verify_or_challenge(
    authorization=request.headers.get("Authorization"),
    intent=intent,
    request={"amount": "1000", ...},
    realm="api.example.com",
)

if isinstance(result, Challenge):
    ...  # Return 402
else:
    credential, receipt = result
    ...  # Return resource
```

#### Custom Intents

```python
from mpay import Credential, Receipt
from mpay.server import VerificationError

class MyChargeIntent:
    name = "charge"

    async def verify(self, credential: Credential, request: dict) -> Receipt:
        if not await self.validate_payment(credential):
            raise VerificationError("Payment invalid")
        return Receipt(
            status="success",
            timestamp=datetime.now().isoformat(),
            reference="...",
        )
```

```python
from mpay.server import intent

@intent(name="charge")
async def my_charge(credential: Credential, request: dict) -> Receipt:
    return Receipt(status="success", ...)
```

### Tempo Method

```python
from mpay.methods.tempo import tempo, TempoAccount, ChargeIntent

account = TempoAccount.from_key("0x...")
account = TempoAccount.from_env("TEMPO_PRIVATE_KEY")

method = tempo(account=account, rpc_url="https://rpc.tempo.xyz")
intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")
```

## Development

```bash
pip install mpay                      # Core only
pip install mpay[tempo]               # With Tempo support
pip install mpay[server]              # With server support (Pydantic)
pip install -e ".[dev,tempo,server]"  # Development install
```

```bash
make install  # Install dependencies
make test     # Run tests
make lint     # Lint
make format   # Format code
make check    # Run all checks
```

## License

MIT OR Apache-2.0
