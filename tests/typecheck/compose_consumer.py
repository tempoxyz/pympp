# pyright: reportPrivateImportUsage=error, reportUnnecessaryTypeIgnoreComment=error
"""Consumer-facing type probes for payment composition."""

from typing import assert_type

from stripe import StripeClient

import mpp.server as server_api
from mpp import Credential, Receipt
from mpp.events import ServerPaymentSuccessPayload
from mpp.methods import CanOfferFn, PaymentSuccessHandler
from mpp.methods import stripe as stripe_module
from mpp.methods.stripe import (
    DepositAddresses,
    MachinePayments,
    PaymentIntentInput,
    create,
)
from mpp.methods.stripe import server as stripe_server
from mpp.methods.tempo import server as tempo_server
from mpp.store import MemoryStore


async def on_payment_success(_payload: ServerPaymentSuccessPayload) -> None:
    pass


methods = tempo_server.charge(
    currency="0x20c0000000000000000000000000000000000000",
    recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
    can_offer=lambda _request: True,
    on_payment_success=on_payment_success,
)
assert_type(methods, list[server_api.ServerMethod])
method = methods[0]
assert_type(method.can_offer, CanOfferFn | None)
assert_type(method.on_payment_success, PaymentSuccessHandler | None)
server = server_api.Mpp(methods=methods, realm="example.com", secret_key="secret")
handler = server.compose(("tempo/charge", {"amount": "1.00", "meta": {"plan": "pro"}}))
assert_type(handler, server_api.ComposedHandler)
assert_type(server_api.compose(handler), server_api.ComposedHandler)


async def check_result() -> None:
    result = await handler(server_api.Request("GET", "https://example.com/paid"))
    assert_type(result, server_api.PaymentResult)
    if isinstance(result, server_api.PaymentVerified):
        assert_type(result.credential, Credential)
        assert_type(result.receipt, Receipt)
    else:
        assert_type(result.challenge, server_api.Response)


server_api.Mpp()  # pyright: ignore[reportCallIssue]

stripe_client = StripeClient("sk_test")
deposit_addresses: DepositAddresses = {"tempo": "0x" + "1" * 40}
machine_payments = create(
    network_id="bn_test",
    livemode=False,
    client=stripe_client,
    deposit_addresses=deposit_addresses,
    store=MemoryStore(),
)
assert_type(machine_payments, MachinePayments)
machine_payments.spt.charge()
machine_payments.tempo.charge()
private_options: PaymentIntentInput = {"customer": "cus_test"}
machine_server = server_api.Mpp(
    methods=machine_payments.default_methods(), realm="example.com", secret_key="secret"
)
machine_server.compose(
    (machine_payments.spt.charge(), {"amount": "0.50", "payment_intent_options": private_options})
)
stripe_server.charge(network_id="bn_test", client=stripe_client)
stripe_module.create(
    network_id="bn_test", livemode=False, client=stripe_client, store=MemoryStore()
)

stripe_server.charge(network_id="bn_test", unknown=True)  # pyright: ignore[reportCallIssue]
server_api.Mpp(methods=machine_payments.default_methods(), realm="example.com", secret_key="secret")
