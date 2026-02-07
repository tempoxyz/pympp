# httpx Client

Payment-enabled HTTP client using httpx.

## Dependencies

```toml
[project]
dependencies = [
    "mpay[tempo]",
]
```

## Basic Usage

The simplest way to make paid requests:

```python
from mpay.client import get
from mpay.methods.tempo import tempo, TempoAccount

account = TempoAccount.from_key("0x...")

response = await get(
    "https://api.example.com/resource",
    methods=[tempo(account=account)],
)
```

## Client Wrapper

For multiple requests, use the `Client` wrapper:

```python
from mpay.client import Client
from mpay.methods.tempo import tempo, TempoAccount

account = TempoAccount.from_key("0x...")

async with Client(methods=[tempo(account=account)]) as client:
    r1 = await client.get("https://api.example.com/a")
    r2 = await client.get("https://api.example.com/b")
```

## Custom Transport

For full control, use `PaymentTransport` with a custom httpx client:

```python
from mpay.client import PaymentTransport
from mpay.methods.tempo import tempo, TempoAccount
import httpx

account = TempoAccount.from_key("0x...")

transport = PaymentTransport(
    methods=[tempo(account=account)],
    inner=httpx.AsyncHTTPTransport(),
)

async with httpx.AsyncClient(transport=transport) as client:
    response = await client.get("https://api.example.com/resource")
```

## Manual Flow

For complete control over the payment flow:

```python
from mpay import Challenge, Credential
from mpay.methods.tempo import tempo, TempoAccount
import httpx

account = TempoAccount.from_key("0x...")
method = tempo(account=account)

async with httpx.AsyncClient() as client:
    # Initial request - expect 402
    res = await client.get("https://api.example.com/resource")
    if res.status_code != 402:
        return res

    # Parse challenge from WWW-Authenticate header
    challenge = Challenge.from_www_authenticate(res.headers["www-authenticate"])

    # Create credential (executes payment)
    credential = await method.create_credential(challenge)

    # Retry with credential
    res2 = await client.get(
        "https://api.example.com/resource",
        headers={"Authorization": credential.to_authorization()},
    )
```
