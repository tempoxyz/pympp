# pyright: reportPrivateImportUsage=error, reportUnnecessaryTypeIgnoreComment=error
"""Consumer-facing type probes for payment composition."""

from typing import assert_type

from stripe import StripeClient

import mpp.server as server_api
from mpp import Challenge, Credential, Receipt
from mpp.events import ServerPaymentSuccessPayload
from mpp.methods import CanOfferFn, PaymentSuccessHandler
from mpp.methods import stripe as stripe_module
from mpp.methods.stripe import DepositAddresses, MachinePayments, create, spt, stripe
from mpp.methods.tempo import ChargeIntent, tempo


async def on_payment_success(_payload: ServerPaymentSuccessPayload) -> None:
    pass


method = tempo(
    intents={"charge": ChargeIntent()},
    currency="usd",
    recipient="acct_consumer",
    can_offer=lambda _request: True,
    on_payment_success=on_payment_success,
)
assert_type(method.can_offer, CanOfferFn | None)
assert_type(method.on_payment_success, PaymentSuccessHandler | None)
server = server_api.Mpp.create(method=method, realm="example.com", secret_key="secret")
options: server_api.ComposeOptions = {"amount": "1.00", "meta": {"plan": "pro"}}
entry: server_api.ComposeEntry = (method, options)
handler = server.compose(entry)
assert_type(handler, server_api.ComposedHandler)
assert_type(server_api.compose(handler), server_api.ComposedHandler)


async def check_result() -> None:
    result = await handler.verify(None)
    assert_type(result, server_api.ComposedResult)
    if isinstance(result, server_api.ComposedChallenges):
        assert_type(result.challenges, tuple[Challenge, ...])
    else:
        assert_type(result, tuple[Credential, Receipt])


server.compose((method, {}))  # pyright: ignore[reportArgumentType]
server.compose((method, {"amount": 1}))  # pyright: ignore[reportArgumentType]
server_api.Mpp.create()  # pyright: ignore[reportCallIssue]
server_api.Mpp.create(method=method, methods=[method])  # pyright: ignore[reportCallIssue]

stripe_client = StripeClient("sk_test")
deposit_addresses: DepositAddresses = {"tempo": "0x" + "1" * 40}
machine_payments = create(
    network_id="bn_test", livemode=False, client=stripe_client, deposit_addresses=deposit_addresses
)
assert_type(machine_payments, MachinePayments)
machine_payments.spt.charge()
machine_payments.tempo.charge()
spt(intents={})
stripe(intents={})
stripe_module.create(network_id="bn_test", livemode=False, client=stripe_client)
stripe(intents={}, unknown=True)  # pyright: ignore[reportCallIssue]
server_api.Mpp.create(
    methods=machine_payments.default_methods(), realm="example.com", secret_key="secret"
)
