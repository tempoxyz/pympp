# Custom Methods

Defining your own payment method for servers and clients.

## Dependencies

```toml
[project]
dependencies = [
    "pympp[server]",
]
```

## Method Definition

A `Method` names the method and intent on the wire and validates route input
(`request_model`, serialized to the wire request) and credential payloads
(`payload_model`):

```python
from pydantic import BaseModel

from mpp.methods import Method


class ChargeRequest(BaseModel):
    amount: str
    currency: str


class ChargePayload(BaseModel):
    payment_intent_id: str


charge = Method(
    name="stripe-pi", intent="charge", request_model=ChargeRequest, payload_model=ChargePayload
)
```

## Server Method

A `ServerMethod` adds the server hooks: `verify` (validation and settlement in
one), or a non-mutating `validate` and a terminal `broadcast`. Hooks receive the
parsed credential and the wire request the challenge carried:

```python
import stripe

from mpp import Receipt
from mpp.server import InternalPaymentError, ServerMethod, VerificationError, VerifyContext


async def verify(context: VerifyContext) -> Receipt:
    request = context.challenge.request
    try:
        payment_intent = stripe.PaymentIntent.retrieve(
            context.credential.payload.payment_intent_id
        )
    except stripe.error.StripeError as e:
        # Not a bad credential: answer 5xx instead of asking the client to pay again.
        raise InternalPaymentError() from e
    if payment_intent.status != "succeeded":
        raise VerificationError("Payment not completed")
    if payment_intent.amount != int(request["amount"]):
        raise VerificationError("Amount mismatch")
    return Receipt.success(reference=payment_intent.id, method="stripe-pi")


method = ServerMethod(method=charge, verify=verify, defaults={"currency": "usd"})
```

## Usage with Server

```python
from fastapi import FastAPI, Request

from mpp import Credential, Receipt
from mpp.server import Mpp, pay

app = FastAPI()
server = Mpp(methods=[method], realm="api.example.com", secret_key="my-server-secret")


@app.get("/resource")
@pay(server.charge(amount="1000"))
async def get_resource(request: Request, credential: Credential, receipt: Receipt):
    return {"data": "paid content"}
```

Pass several methods, such as `[tempo.charge(...), method]`, to offer each of
them on one route; the client pays the first it supports.

## Client Method

A `ClientMethod` creates the serialized credential for a challenge:

```python
from mpp import Credential
from mpp.client import ClientMethod, CredentialParams


async def create_credential(params: CredentialParams) -> str:
    payment_intent_id = await confirm_payment(params.challenge.request)
    return Credential(
        challenge=params.challenge.to_echo(),
        payload={"payment_intent_id": payment_intent_id},
    ).to_authorization()


client_method = ClientMethod(method=charge, create_credential=create_credential)
```
