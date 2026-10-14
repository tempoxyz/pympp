"""Client-side amount caps and ``expected_recipients`` policy for Tempo charges."""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mpp import Challenge
from mpp.methods.tempo import CHAIN_ID, MACH, PATH_USD, USDC, ChargeIntent, TempoAccount, tempo

TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
SPLIT_RECIPIENT = "0xAbCdEf0000000000000000000000000000000001"
OTHER = "0x2222222222222222222222222222222222222222"
CUSTOM_TOKEN = "0x20c00000000000000000000000000000000000ff"


def swap_case(address: str) -> str:
    """Return the address with its hex digits in the opposite case."""
    return "0x" + address[2:].swapcase()


def make_challenge(
    amount: str = "1000",
    recipient: str = RECIPIENT,
    splits: list[dict[str, str]] | None = None,
    currency: str = PATH_USD,
) -> Challenge:
    request: dict[str, Any] = {"amount": amount, "currency": currency, "recipient": recipient}
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
    ("policy", "challenge", "error"),
    [
        pytest.param({}, make_challenge(amount=str(10**30)), None, id="unset"),
        # max_atomic_amount: base units
        pytest.param(
            {"max_atomic_amount": 1000}, make_challenge(amount="999"), None, id="atomic-below"
        ),
        pytest.param(
            {"max_atomic_amount": 1000}, make_challenge(amount="1000"), None, id="atomic-equal"
        ),
        pytest.param(
            {"max_atomic_amount": 1000},
            make_challenge(amount="1001"),
            "at most 1000 base units",
            id="atomic-above",
        ),
        pytest.param(
            {"max_atomic_amount": "1000"},
            make_challenge(amount="1001"),
            "at most 1000 base units",
            id="atomic-digit-string",
        ),
        pytest.param(
            {"max_atomic_amount": 0}, make_challenge(amount="1"), "at most 0", id="atomic-zero"
        ),
        pytest.param(
            {"max_atomic_amount": 1000},
            make_challenge(amount="1000", splits=SPLIT),
            None,
            id="atomic-includes-splits",
        ),
        pytest.param(
            {"max_atomic_amount": 1000},
            make_challenge(amount="0x10"),
            "integer in base units",
            id="amount-not-decimal",
        ),
        # max_amount: token units
        pytest.param({"max_amount": "1"}, make_challenge(amount="999999"), None, id="token-below"),
        pytest.param({"max_amount": "1"}, make_challenge(amount="1000000"), None, id="token-equal"),
        pytest.param(
            {"max_amount": "1"},
            make_challenge(amount="1000001"),
            r"at most 1 \(1000000 base units\)",
            id="token-above",
        ),
        pytest.param(
            {"max_amount": Decimal("0.5")},
            make_challenge(amount="500001", currency=USDC),
            "500000 base units",
            id="token-decimal-usdc",
        ),
        pytest.param(
            {"max_amount": "0.5"},
            make_challenge(amount="500000", currency=swap_case(MACH)),
            None,
            id="token-known-currency-case-insensitive",
        ),
        pytest.param(
            {"max_amount": "1", "decimals": 18},
            make_challenge(amount="1000001"),
            "1000000 base units",
            id="token-metadata-over-decimals",
        ),
        pytest.param(
            {"max_amount": "1", "decimals": 2},
            make_challenge(amount="100", currency=CUSTOM_TOKEN),
            None,
            id="token-custom-currency-decimals-equal",
        ),
        pytest.param(
            {"max_amount": "1", "decimals": 2},
            make_challenge(amount="101", currency=CUSTOM_TOKEN),
            r"\(100 base units\)",
            id="token-custom-currency-decimals-above",
        ),
        pytest.param(
            {"max_amount": "1"},
            make_challenge(amount="1", currency=CUSTOM_TOKEN),
            "max_amount requires decimals",
            id="token-custom-currency-no-decimals",
        ),
        pytest.param(
            {"max_amount": "0.0000001"},
            make_challenge(amount="0"),
            "fractional base units",
            id="token-finer-than-decimals",
        ),
        pytest.param(
            {"max_atomic_amount": 500, "max_amount": "1"},
            make_challenge(amount="501"),
            "at most 500 base units",
            id="both-caps-atomic-stricter",
        ),
        pytest.param(
            {"max_atomic_amount": 10**9, "max_amount": "0.0001"},
            make_challenge(amount="101"),
            r"\(100 base units\)",
            id="both-caps-token-stricter",
        ),
        # expected_recipients
        pytest.param(
            {"expected_recipients": [RECIPIENT]}, make_challenge(), None, id="recipient-allowed"
        ),
        pytest.param(
            {"expected_recipients": [RECIPIENT.lower()]},
            make_challenge(recipient=RECIPIENT),
            None,
            id="recipient-allowed-lowercase-config",
        ),
        pytest.param(
            {"expected_recipients": [RECIPIENT]},
            make_challenge(recipient=swap_case(RECIPIENT)),
            None,
            id="recipient-allowed-swapped-case-challenge",
        ),
        pytest.param(
            {"expected_recipients": [OTHER]},
            make_challenge(),
            "recipient '0x742d35Cc",
            id="recipient-disallowed",
        ),
        pytest.param(
            {"expected_recipients": []},
            make_challenge(),
            "expected recipients",
            id="empty-allowlist",
        ),
        pytest.param(
            {"expected_recipients": [RECIPIENT, swap_case(SPLIT_RECIPIENT)]},
            make_challenge(splits=SPLIT),
            None,
            id="split-recipient-allowed",
        ),
        pytest.param(
            {"expected_recipients": [RECIPIENT]},
            make_challenge(splits=SPLIT),
            "split recipient '0xAbCdEf",
            id="split-recipient-disallowed",
        ),
        pytest.param(
            {"max_atomic_amount": 1000, "expected_recipients": [OTHER]},
            make_challenge(amount="10"),
            "recipient",
            id="amount-ok-recipient-disallowed",
        ),
        pytest.param(
            {"max_amount": "0.001", "expected_recipients": [RECIPIENT]},
            make_challenge(amount="1001"),
            r"at most 0.001 \(1000 base units\)",
            id="recipient-ok-amount-disallowed",
        ),
    ],
)
async def test_charge_policy(
    policy: dict[str, Any],
    challenge: Challenge,
    error: str | None,
) -> None:
    method = tempo(
        account=TempoAccount.from_key(TEST_PRIVATE_KEY),
        intents={"charge": ChargeIntent()},
        **policy,
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
        max_atomic_amount=1000,
        max_amount="0.0005",
        expected_recipients=[RECIPIENT],
    )

    with (
        patch("mpp.methods.tempo.client._rpc_call", AsyncMock()) as rpc,
        patch("pytempo.TempoTransaction.create") as create,
    ):
        with pytest.raises(ValueError, match="at most 1000 base units"):
            await method.create_credential(make_challenge(amount="1001"))
        with pytest.raises(ValueError, match=r"\(500 base units\)"):
            await method.create_credential(make_challenge(amount="501"))
        with pytest.raises(ValueError, match="recipient"):
            await method.create_credential(make_challenge(amount="1", recipient=OTHER))

    rpc.assert_not_called()
    create.assert_not_called()


@pytest.mark.parametrize(
    ("kwargs", "attribute", "expected"),
    [
        pytest.param({}, "max_atomic_amount", None, id="atomic-unset"),
        pytest.param({}, "max_amount", None, id="token-unset"),
        pytest.param({}, "expected_recipients", None, id="recipients-unset"),
        pytest.param({}, "decimals", 6, id="decimals-default"),
        pytest.param({"max_atomic_amount": 1000}, "max_atomic_amount", 1000, id="atomic-int"),
        pytest.param({"max_atomic_amount": "1000"}, "max_atomic_amount", 1000, id="atomic-str"),
        pytest.param({"max_amount": "1.50"}, "max_amount", Decimal("1.50"), id="token-str"),
        pytest.param({"max_amount": Decimal("2")}, "max_amount", Decimal("2"), id="token-decimal"),
        pytest.param({"decimals": 18}, "decimals", 18, id="decimals-explicit"),
        pytest.param(
            {"expected_recipients": [RECIPIENT, SPLIT_RECIPIENT]},
            "expected_recipients",
            (RECIPIENT, SPLIT_RECIPIENT),
            id="recipients-tuple",
        ),
    ],
)
def test_tempo_stores_charge_policy(kwargs: dict[str, Any], attribute: str, expected: Any) -> None:
    method = tempo(intents={"charge": ChargeIntent()}, **kwargs)

    assert getattr(method, attribute) == expected


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        pytest.param({"max_atomic_amount": -1}, "max_atomic_amount", id="atomic-negative"),
        pytest.param({"max_atomic_amount": True}, "max_atomic_amount", id="atomic-bool"),
        pytest.param({"max_atomic_amount": 1.5}, "max_atomic_amount", id="atomic-float"),
        pytest.param({"max_atomic_amount": "1.5"}, "max_atomic_amount", id="atomic-decimal-str"),
        pytest.param({"max_atomic_amount": "-1"}, "max_atomic_amount", id="atomic-negative-str"),
        pytest.param({"max_atomic_amount": ""}, "max_atomic_amount", id="atomic-empty-str"),
        pytest.param({"max_amount": 1}, "use max_atomic_amount", id="token-int"),
        pytest.param({"max_amount": 0.01}, "use max_atomic_amount", id="token-float"),
        pytest.param({"max_amount": "abc"}, "Invalid max_amount", id="token-not-number"),
        pytest.param({"max_amount": "-1"}, "non-negative", id="token-negative"),
        pytest.param({"max_amount": "NaN"}, "finite", id="token-nan"),
        pytest.param({"max_amount": Decimal("Infinity")}, "finite", id="token-infinity"),
        pytest.param({"expected_recipients": RECIPIENT}, "sequence", id="string-recipients"),
        pytest.param({"expected_recipients": ["0x1234"]}, "recipient address", id="short-address"),
        pytest.param({"expected_recipients": [123]}, "recipient address", id="non-string-address"),
    ],
)
def test_tempo_rejects_invalid_charge_policy(kwargs: dict[str, Any], error: str) -> None:
    with pytest.raises(ValueError, match=error):
        tempo(intents={"charge": ChargeIntent()}, **kwargs)
