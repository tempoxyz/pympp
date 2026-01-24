# mpay

HTTP Payment Authentication for Python. Implements the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ietf-httpauth-payment/) with pluggable payment methods & intents.

## Install

```bash
pip install mpay

# With Tempo support
pip install mpay[tempo]

# With server support (Pydantic schemas)
pip install mpay[server]
```

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

    # Payment required — send 402 response with challenge
    if isinstance(result, Challenge):
        return Response(
            status=402,
            headers={"WWW-Authenticate": result.to_www_authenticate("api.example.com")},
        )

    # Payment verified — return resource
    credential, receipt = result
    return Response(
        {"data": "..."},
        headers={"Payment-Receipt": receipt.to_payment_receipt()},
    )
```

### Client

#### Automatic: Client Wrapper

The easiest way to use mpay on the client is with the `Client` wrapper that automatically handles 402 responses:

```python
from mpay.client import Client
from mpay.methods.tempo import tempo, TempoAccount

account = TempoAccount.from_key("0x...")

async with Client(methods=[tempo(account=account, rpc_url="https://rpc.tempo.xyz")]) as client:
    # Handles 402 automatically
    r1 = await client.get("https://api.example.com/a")
    r2 = await client.get("https://api.example.com/b")
```

#### Automatic: One-liner

For simple requests without connection pooling:

```python
from mpay.client import get
from mpay.methods.tempo import tempo, TempoAccount

account = TempoAccount.from_key("0x...")

# Simple one-liner — handles 402 automatically
response = await get(
    "https://api.example.com/resource",
    methods=[tempo(account=account, rpc_url="https://rpc.tempo.xyz")],
)
```

#### Automatic: Custom httpx Transport

If you prefer to use your own httpx client, use `PaymentTransport`:

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

For more control, you can manually create credentials:

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

    # Retry with credential
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

# Serialize to header
header = challenge.to_www_authenticate("api.example.com")

# Parse from header
parsed = Challenge.from_www_authenticate(header)
```

#### `Credential`

The credential passed to the `verify` function, containing the challenge ID and client payload.

```python
from mpay import Credential

credential = Credential(
    id="challenge-id",
    payload={"hash": "0x..."},
    source="did:pkh:eip155:1:0x...",  # Optional payer DID
)

# Serialize to header
header = credential.to_authorization()

# Parse from header
parsed = Credential.from_authorization(header)
```

#### `Receipt`

Payment receipt returned after successful verification, sent via the `Payment-Receipt` header.

```python
from mpay import Receipt

receipt = Receipt(
    status="success",
    timestamp="2024-01-20T12:00:00Z",
    reference="0x...",
)

# Serialize to header
header = receipt.to_payment_receipt()

# Parse from header
parsed = Receipt.from_payment_receipt(header)
```

### Server

#### `verify_or_challenge`

Core function for server-side payment verification.

```python
from mpay.server import verify_or_challenge

result = await verify_or_challenge(
    authorization=request.headers.get("Authorization"),
    intent=intent,
    request={"amount": "1000", ...},
    realm="api.example.com",
)

if isinstance(result, Challenge):
    # No valid credential — return 402
    ...
else:
    credential, receipt = result
    # Payment verified — return resource
    ...
```

#### Custom Intents

##### Class-based

```python
from mpay import Credential, Receipt
from mpay.server import VerificationError

class MyChargeIntent:
    name = "charge"

    async def verify(self, credential: Credential, request: dict) -> Receipt:
        # Custom verification logic
        if not await self.validate_payment(credential):
            raise VerificationError("Payment invalid")

        return Receipt(
            status="success",
            timestamp=datetime.now().isoformat(),
            reference="...",
        )
```

##### Functional

```python
from mpay.server import intent

@intent(name="charge")
async def my_charge(credential: Credential, request: dict) -> Receipt:
    # Custom verification logic
    return Receipt(status="success", ...)
```

### Tempo Method

```python
from mpay.methods.tempo import tempo, TempoAccount, ChargeIntent

# Create account
account = TempoAccount.from_key("0x...")
# Or from environment
account = TempoAccount.from_env("TEMPO_PRIVATE_KEY")

# Client-side method
method = tempo(account=account, rpc_url="https://rpc.tempo.xyz")

# Server-side intent
intent = ChargeIntent(rpc_url="https://rpc.tempo.xyz")
```

## Development

```bash
make install  # Install dependencies
make test     # Run tests
make lint     # Lint
make format   # Format code
make check    # Run all checks (lint + format-check + test)
```

## License

MIT OR Apache-2.0
