"""Stripe payment method for HTTP 402 authentication: the charge intent.

Example:
    # Client-side
    from mpp.client import Client
    from mpp.methods.stripe import client as stripe

    async def create_spt(params):
        # Proxy to your server endpoint that creates an SPT
        ...
        return spt_token

    async with Client(
        methods=[stripe.charge(create_token=create_spt, payment_method="pm_card_visa")]
    ) as client:
        response = await client.get("https://api.example.com/resource")

    # Server-side
    from mpp.server import Mpp
    from mpp.methods.stripe import server as stripe

    mpp = Mpp(
        methods=stripe.charge(
            secret_key="sk_...",
            network_id="bn_...",
            payment_method_types=["card"],
            currency="usd",
        ),
    )
"""

from mpp.methods.stripe import client as client
from mpp.methods.stripe import server as server
from mpp.methods.stripe.client import StripeMethod as StripeMethod
from mpp.methods.stripe.intents import ChargeIntent as ChargeIntent
from mpp.methods.stripe.machine_payments import DepositAddresses as DepositAddresses
from mpp.methods.stripe.machine_payments import MachinePayments as MachinePayments
from mpp.methods.stripe.machine_payments import create as create
from mpp.methods.stripe.payment_intent_options import PaymentIntentContext as PaymentIntentContext
from mpp.methods.stripe.payment_intent_options import PaymentIntentInput as PaymentIntentInput
from mpp.methods.stripe.payment_intent_options import PaymentIntentOptions as PaymentIntentOptions
from mpp.methods.stripe.schemas import ChargeInput as ChargeInput
from mpp.methods.stripe.schemas import ChargeRequest as ChargeRequest
from mpp.methods.stripe.schemas import StripeCredentialPayload as StripeCredentialPayload
