"""Stripe payment method for HTTP 402 authentication.

Uses Stripe's Shared Payment Token (SPT) flow for one-time charges.

Example:
    # Client-side
    from mpp.client import get
    from mpp.methods.stripe import stripe, ChargeIntent

    async def create_spt(params):
        # Proxy to your server endpoint that creates an SPT
        ...
        return spt_token

    response = await get(
        "https://api.example.com/resource",
        methods=[stripe(
            create_token=create_spt,
            payment_method="pm_card_visa",
            intents={},
        )],
    )

    # Server-side
    from mpp.server import Mpp
    from mpp.methods.stripe import stripe, ChargeIntent

    server = Mpp.create(
        method=stripe(
            network_id="bn_...",
            payment_method_types=["card"],
            currency="usd",
            decimals=2,
            intents={"charge": ChargeIntent(secret_key="sk_...")},
        ),
    )
"""

from mpp.methods.stripe.client import StripeMethod, stripe
from mpp.methods.stripe.intents import ChargeIntent
from mpp.methods.stripe.schemas import ChargeRequest, StripeCredentialPayload
