"""Stripe payment method for HTTP 402 authentication.

Prefer ``spt`` for Shared Payment Tokens; ``stripe`` is a deprecated compatibility name.

Example:
    # Client-side
    from mpp.client import get
    from mpp.methods.stripe import spt, ChargeIntent

    async def create_spt(params):
        # Proxy to your server endpoint that creates an SPT
        ...
        return spt_token

    response = await get(
        "https://api.example.com/resource",
        methods=[spt(
            create_token=create_spt,
            payment_method="pm_card_visa",
            intents={},
        )],
    )

    # Server-side
    from mpp.server import Mpp
    from mpp.methods.stripe import spt, ChargeIntent

    server = Mpp.create(
        method=spt(
            network_id="bn_...",
            payment_method_types=["card"],
            currency="usd",
            decimals=2,
            intents={"charge": ChargeIntent(secret_key="sk_...")},
        ),
    )
"""

from mpp.methods.stripe.client import StripeMethod as StripeMethod
from mpp.methods.stripe.client import spt as spt
from mpp.methods.stripe.client import stripe as stripe
from mpp.methods.stripe.intents import ChargeIntent as ChargeIntent
from mpp.methods.stripe.machine_payments import DepositAddresses as DepositAddresses
from mpp.methods.stripe.machine_payments import MachinePayments as MachinePayments
from mpp.methods.stripe.machine_payments import create as create
from mpp.methods.stripe.schemas import ChargeRequest as ChargeRequest
from mpp.methods.stripe.schemas import StripeCredentialPayload as StripeCredentialPayload
