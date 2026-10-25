"""Crypto PaymentIntent amounts must not exceed the settled on-chain amount."""

import pytest

from mpp import Receipt
from mpp.methods.stripe.crypto_payment_recorder import record_crypto_payment
from tests.test_stripe_machine_payments import FakeStripeClient


@pytest.mark.parametrize("network", ["tempo", "base", "solana"])
@pytest.mark.parametrize(
    "amount,cents",
    [
        ("0", 0),
        ("9999", 0),
        ("10000", 1),
        ("14999", 1),
        ("15000", 1),
        ("19999", 1),
        ("20000", 2),
        ("9007199254749999", 900719925474),
    ],
)
async def test_records_whole_cents_only(network: str, amount: str, cents: int) -> None:
    client = FakeStripeClient()
    await record_crypto_payment(
        client=client,
        network=network,
        metadata=None,
        credential=None,
        request={"amount": amount},
        receipt=Receipt.success("0xtest", method="tempo"),
    )

    if cents == 0:
        assert client.payment_intents.calls == []
    else:
        assert len(client.payment_intents.calls) == 1
        params, _ = client.payment_intents.calls[0]
        assert params["amount"] == cents
