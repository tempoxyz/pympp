# httpx Client

Payment-enabled HTTP client using httpx.

## Dependencies

```toml
[project]
dependencies = [
    "pympp[tempo]",
]
```

## Basic Usage

`Mpp` pays `402` challenges automatically:

```python
from mpp.client import Mpp
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo

account = TempoAccount.from_key("0x...")

async with Mpp(methods=[tempo.charge(account=account)]) as mpp:
    r1 = await mpp.fetch("https://api.example.com/a")
    r2 = await mpp.fetch("https://api.example.com/b")
```

## Custom Client

To use your own `httpx.AsyncClient`, pass it the payment transport:

```python
import httpx

async with Mpp(methods=[tempo.charge(account=account)]) as mpp:
    async with httpx.AsyncClient(transport=mpp.payment_transport) as client:
        response = await client.get("https://api.example.com/resource")
```

## Manual Flow

For complete control over the payment flow:

```python
import httpx

from mpp import Challenge
from mpp.runtime import PaymentRuntime

payments = PaymentRuntime([tempo.charge(account=account)])

async with httpx.AsyncClient() as client:
    # Initial request - expect 402
    res = await client.get("https://api.example.com/resource")
    if res.status_code != 402:
        return res

    # Parse challenges from WWW-Authenticate headers
    challenges = [
        Challenge.from_www_authenticate(value)
        for value in res.headers.get_list("www-authenticate")
    ]

    # Pick a challenge and create its credential (executes payment)
    challenge, method = payments.match_challenge(challenges)
    credential = await payments.create_credential(challenge, method)

    # Retry with credential
    res2 = await client.get(
        "https://api.example.com/resource",
        headers={challenge.credential_header: credential.to_authorization()},
    )
```
