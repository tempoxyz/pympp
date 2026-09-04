# pyright: reportUnnecessaryTypeIgnoreComment=error
"""Consumer-facing type probes for payment composition."""

from typing import assert_type

import mpp.server as server_api
from mpp import Challenge, Credential, Receipt
from mpp.events import ServerPaymentSuccessPayload
from mpp.methods import CanOfferFn, PaymentSuccessHandler
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
