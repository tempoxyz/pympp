"""Stripe client methods.

Example::

    from mpp.client import Mpp
    from mpp.stripe import client as stripe

    async def create_token(params: stripe.TokenParams) -> str:
        ...  # ask your backend to create an SPT for `params`

    mppx = Mpp(methods=[stripe.charge(create_token=create_token, payment_method="pm_...")])
"""

from mpp.stripe.client._charge import ChargeContext, CreateToken, TokenParams, charge, stripe

__all__ = ["ChargeContext", "CreateToken", "TokenParams", "charge", "stripe"]
