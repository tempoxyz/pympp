"""Stripe server methods.

SPT charge::

    from mpp.server import Mpp
    from mpp.stripe import server as stripe

    mppx = Mpp(methods=[stripe.charge(secret_key="sk_...", network_id="internal",
                                       payment_method_types=["card"])])
    handler = mppx.charge(amount="1", currency="usd", decimals=2)

Machine payments (SPT + crypto rails settled into Stripe deposit addresses)::

    machine_payments = stripe.create(client=StripeHttpClient("sk_..."), network_id="profile_...",
                                     livemode=False, store=store.memory(),
                                     deposit_addresses={"tempo": "0x..."})
    mppx = Mpp(methods=machine_payments.default_methods())
"""

from mpp.stripe._internal.payment_intent import OptionsInput, ResolveOptions
from mpp.stripe.server._analytics import build_analytics, sdk_identifier
from mpp.stripe.server._charge import MINIMUM_CHARGE_AMOUNTS, charge
from mpp.stripe.server._deposit_address import find_or_create_deposit_address
from mpp.stripe.server._machine_payments import (
    CustomRail,
    DepositAddressResolver,
    MachinePayments,
    Network,
    create,
    with_payment_intent_input,
)
from mpp.stripe.server._record_payment import record_crypto_payment

spt = charge
"""Alias of :func:`charge` (mppx ``stripe.spt``)."""

__all__ = [
    "MINIMUM_CHARGE_AMOUNTS",
    "CustomRail",
    "DepositAddressResolver",
    "MachinePayments",
    "Network",
    "OptionsInput",
    "ResolveOptions",
    "build_analytics",
    "charge",
    "create",
    "find_or_create_deposit_address",
    "record_crypto_payment",
    "sdk_identifier",
    "spt",
    "with_payment_intent_input",
]
