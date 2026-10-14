"""Client-side ``max_amount`` and ``expected_recipients`` policy for Tempo charges."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mpp import Challenge
from mpp.methods.tempo import CHAIN_ID, PATH_USD, ChargeIntent, TempoAccount, tempo

TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
SPLIT_RECIPIENT = "0xAbCdEf0000000000000000000000000000000001"
OTHER = "0x2222222222222222222222222222222222222222"


def swap_case(address: str) -> str:
    """Return the address with its hex digits in the opposite case."""
    return "0x" + address[2:].swapcase()


def make_challenge(
    amount: str = "1000",
    recipient: str = RECIPIENT,
    splits: list[dict[str, str]] | None = None,
) -> Challenge:
    request: dict[str, Any] = {"amount": amount, "currency": PATH_USD, "recipient": recipient}
    if splits is not None:
        request["methodDetails"] = {"splits": splits}
    return Challenge(
        id="policy-challenge",
        method="tempo",
        intent="charge",
        realm="api.example.com",
        request=request,
    )


SPLIT = [{"amount": "100", "recipient": SPLIT_RECIPIENT}]


@pytest.mark.parametrize(
    ("max_amount", "expected_recipients", "challenge", "error"),
    [
        pytest.param(None, None, make_challenge(amount=str(10**30)), None, id="unset"),
        pytest.param(1000, None, make_challenge(amount="999"), None, id="amount-below-cap"),
        pytest.param(1000, None, make_challenge(amount="1000"), None, id="amount-equal-cap"),
        pytest.param(
            1000, None, make_challenge(amount="1001"), "at most 1000", id="amount-above-cap"
        ),
        pytest.param(0, None, make_challenge(amount="1"), "at most 0", id="zero-cap"),
        pytest.param(
            1000, None, make_challenge(amount="1000", splits=SPLIT), None, id="cap-includes-splits"
        ),
        pytest.param(
            1000,
            None,
            make_challenge(amount="0x10"),
            "integer in base units",
            id="amount-not-decimal",
        ),
        pytest.param(None, [RECIPIENT], make_challenge(), None, id="recipient-allowed"),
        pytest.param(
            None,
            [RECIPIENT.lower()],
            make_challenge(recipient=RECIPIENT),
            None,
            id="recipient-allowed-lowercase-config",
        ),
        pytest.param(
            None,
            [RECIPIENT],
            make_challenge(recipient=swap_case(RECIPIENT)),
            None,
            id="recipient-allowed-swapped-case-challenge",
        ),
        pytest.param(
            None,
            [OTHER],
            make_challenge(),
            "recipient '0x742d35Cc",
            id="recipient-disallowed",
        ),
        pytest.param(None, [], make_challenge(), "expected recipients", id="empty-allowlist"),
        pytest.param(
            None,
            [RECIPIENT, swap_case(SPLIT_RECIPIENT)],
            make_challenge(splits=SPLIT),
            None,
            id="split-recipient-allowed",
        ),
        pytest.param(
            None,
            [RECIPIENT],
            make_challenge(splits=SPLIT),
            "split recipient '0xAbCdEf",
            id="split-recipient-disallowed",
        ),
        pytest.param(
            1000,
            [OTHER],
            make_challenge(amount="10"),
            "recipient",
            id="amount-ok-recipient-disallowed",
        ),
        pytest.param(
            1000,
            [RECIPIENT],
            make_challenge(amount="1001"),
            "at most 1000",
            id="recipient-ok-amount-disallowed",
        ),
    ],
)
async def test_charge_policy(
    max_amount: int | None,
    expected_recipients: list[str] | None,
    challenge: Challenge,
    error: str | None,
) -> None:
    method = tempo(
        account=TempoAccount.from_key(TEST_PRIVATE_KEY),
        intents={"charge": ChargeIntent()},
        max_amount=max_amount,
        expected_recipients=expected_recipients,
    )
    build = AsyncMock(return_value=("0xdeadbeef", CHAIN_ID))
    rpc = AsyncMock(side_effect=AssertionError("unexpected RPC call"))

    with (
        patch.object(method, "_build_tempo_transfer", build),
        patch("mpp.methods.tempo.client._rpc_call", rpc),
    ):
        if error is not None:
            with pytest.raises(ValueError, match=error):
                await method.create_credential(challenge)
            build.assert_not_awaited()
            rpc.assert_not_called()
            return
        credential = await method.create_credential(challenge)

    rpc.assert_not_called()
    assert credential.payload["signature"] == "0xdeadbeef"
    build.assert_awaited_once()
    await_args = build.await_args
    assert await_args is not None
    kwargs = await_args.kwargs
    assert kwargs["amount"] == challenge.request["amount"]
    assert kwargs["recipient"] == challenge.request["recipient"]


async def test_rejected_charge_is_never_signed() -> None:
    method = tempo(
        account=TempoAccount.from_key(TEST_PRIVATE_KEY),
        intents={"charge": ChargeIntent()},
        max_amount=1000,
        expected_recipients=[RECIPIENT],
    )

    with (
        patch("mpp.methods.tempo.client._rpc_call", AsyncMock()) as rpc,
        patch("pytempo.TempoTransaction.create") as create,
    ):
        with pytest.raises(ValueError, match="at most 1000"):
            await method.create_credential(make_challenge(amount="1001"))
        with pytest.raises(ValueError, match="recipient"):
            await method.create_credential(make_challenge(recipient=OTHER))

    rpc.assert_not_called()
    create.assert_not_called()


def test_tempo_stores_charge_policy() -> None:
    method = tempo(
        intents={"charge": ChargeIntent()},
        max_amount=1_000_000,
        expected_recipients=[RECIPIENT, SPLIT_RECIPIENT],
    )

    assert method.max_amount == 1_000_000
    assert method.expected_recipients == (RECIPIENT, SPLIT_RECIPIENT)


def test_tempo_charge_policy_defaults_to_unset() -> None:
    method = tempo(intents={"charge": ChargeIntent()})

    assert method.max_amount is None
    assert method.expected_recipients is None


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        pytest.param({"max_amount": -1}, "max_amount", id="negative-cap"),
        pytest.param({"max_amount": True}, "max_amount", id="bool-cap"),
        pytest.param({"max_amount": "1000"}, "max_amount", id="string-cap"),
        pytest.param({"max_amount": 0.01}, "max_amount", id="float-cap"),
        pytest.param({"expected_recipients": RECIPIENT}, "sequence", id="string-recipients"),
        pytest.param({"expected_recipients": ["0x1234"]}, "recipient address", id="short-address"),
        pytest.param({"expected_recipients": [123]}, "recipient address", id="non-string-address"),
    ],
)
def test_tempo_rejects_invalid_charge_policy(kwargs: dict[str, Any], error: str) -> None:
    with pytest.raises(ValueError, match=error):
        tempo(intents={"charge": ChargeIntent()}, **kwargs)
