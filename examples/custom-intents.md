# Custom Intents

Creating custom payment intents for different payment methods.

## Dependencies

```toml
[project]
dependencies = [
    "pympp[server]",
]
```

## Intent Protocol

Intents verify credentials and return receipts. Any class implementing this protocol works:

```python
from mpp import Credential, Receipt
from mpp.server import VerificationError

class MyIntent:
    name = "charge"

    async def verify(self, credential: Credential, request: dict) -> Receipt:
        # Validate the payment
        if not await self.validate_payment(credential, request):
            raise VerificationError("Payment invalid")

        return Receipt(
            status="success",
            timestamp=datetime.now(UTC).isoformat(),
            reference="tx_123",
        )

    async def validate_payment(self, credential: Credential, request: dict) -> bool:
        # Your validation logic here
        return True
```

## Function-Based Intent

Use the `@intent` decorator for simpler cases:

```python
from mpp import Credential, Receipt
from mpp.server import intent

@intent(name="charge")
async def my_charge(credential: Credential, request: dict) -> Receipt:
    # Validate and process payment
    return Receipt.success(reference="tx_123")
```

## Stripe Intent Example

```python
import stripe
from mpp import Credential, Receipt
from mpp.server import VerificationError

class StripeChargeIntent:
    name = "charge"

    def __init__(self, api_key: str):
        stripe.api_key = api_key

    async def verify(self, credential: Credential, request: dict) -> Receipt:
        try:
            # Verify the payment intent
            payment_intent = stripe.PaymentIntent.retrieve(
                credential.payload["payment_intent_id"]
            )

            if payment_intent.status != "succeeded":
                raise VerificationError("Payment not completed")

            if payment_intent.amount != int(request["amount"]):
                raise VerificationError("Amount mismatch")

            return Receipt(
                status="success",
                timestamp=payment_intent.created,
                reference=payment_intent.id,
            )
        except stripe.error.StripeError as e:
            raise VerificationError(str(e))
```

## Usage with Server

```python
from fastapi import FastAPI, Request
from mpp import Credential, Receipt
from mpp.server import requires_payment

app = FastAPI()
intent = StripeChargeIntent(api_key="sk_...")

@app.get("/resource")
@requires_payment(
    intent=intent,
    request={"amount": "1000", "currency": "usd"},
    realm="api.example.com",
    secret_key="my-server-secret",
)
async def get_resource(request: Request, credential: Credential, receipt: Receipt):
    return {"data": "paid content"}
```

## Multiple Methods

Support multiple payment methods by checking the credential:

```python
from mpp import Credential, Receipt
from mpp.server import VerificationError

class MultiMethodIntent:
    name = "charge"

    def __init__(self, tempo_rpc: str, stripe_key: str):
        self.tempo = ChargeIntent(rpc_url=tempo_rpc)
        self.stripe = StripeChargeIntent(api_key=stripe_key)

    async def verify(self, credential: Credential, request: dict) -> Receipt:
        # Route based on credential source
        if credential.source.startswith("0x"):
            return await self.tempo.verify(credential, request)
        elif credential.source.startswith("cus_"):
            return await self.stripe.verify(credential, request)
        else:
            raise VerificationError("Unknown payment method")
```
