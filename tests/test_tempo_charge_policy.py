"""Client-side amount caps and ``expected_recipients`` policy for Tempo charges."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mpp import Challenge
from mpp.extensions.mcp import McpClient
from mpp.extensions.mcp.types import MCPChallenge
from mpp.methods.tempo import CHAIN_ID, PATH_USD, ChargeIntent, TempoAccount, tempo
from mpp.methods.tempo.client import TempoMethod
from mpp.runtime import PaymentRuntime

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
    challenge_id: str = "policy-challenge",
) -> Challenge:
    request: dict[str, Any] = {"amount": amount, "currency": PATH_USD, "recipient": recipient}
    if splits is not None:
        request["methodDetails"] = {"splits": splits}
    return Challenge(
        id=challenge_id,
        method="tempo",
        intent="charge",
        realm="api.example.com",
        request=request,
    )


def make_method(**policy: Any) -> TempoMethod:
    return tempo(
        account=TempoAccount.from_key(TEST_PRIVATE_KEY),
        intents={"charge": ChargeIntent()},
        **policy,
    )


SPLIT = [{"amount": "100", "recipient": SPLIT_RECIPIENT}]
TOKEN_CAP = {"max_amount": "1", "max_amount_decimals": 6}


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
            "exceeds max_atomic_amount",
            id="atomic-above",
        ),
        pytest.param(
            {"max_atomic_amount": "1000"},
            make_challenge(amount="1001"),
            "exceeds max_atomic_amount",
            id="atomic-digit-string",
        ),
        pytest.param(
            {"max_atomic_amount": 0},
            make_challenge(amount="1"),
            "exceeds max_atomic_amount",
            id="atomic-zero",
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
        # max_amount: token units, parsed with max_amount_decimals
        pytest.param(TOKEN_CAP, make_challenge(amount="999999"), None, id="token-below"),
        pytest.param(TOKEN_CAP, make_challenge(amount="1000000"), None, id="token-equal"),
        pytest.param(
            TOKEN_CAP,
            make_challenge(amount="1000001"),
            "exceeds max_amount",
            id="token-above",
        ),
        pytest.param(
            {"max_amount": Decimal("0.5"), "max_amount_decimals": 6},
            make_challenge(amount="500001"),
            "exceeds max_amount",
            id="token-decimal",
        ),
        pytest.param(
            {"max_amount": "1", "max_amount_decimals": 2},
            make_challenge(amount="100"),
            None,
            id="token-two-decimals-equal",
        ),
        pytest.param(
            {"max_amount": "1", "max_amount_decimals": 2},
            make_challenge(amount="101"),
            "exceeds max_amount",
            id="token-two-decimals-above",
        ),
        pytest.param(
            {"max_amount": "0.000001", "max_amount_decimals": 6},
            make_challenge(amount="1"),
            None,
            id="token-one-base-unit",
        ),
        pytest.param(
            {"max_amount": "0", "max_amount_decimals": 6},
            make_challenge(amount="1"),
            "exceeds max_amount",
            id="token-zero",
        ),
        pytest.param(
            {"max_atomic_amount": 500, **TOKEN_CAP},
            make_challenge(amount="501"),
            "exceeds max_atomic_amount",
            id="both-caps-atomic-stricter",
        ),
        pytest.param(
            {"max_atomic_amount": 10**9, "max_amount": "0.0001", "max_amount_decimals": 6},
            make_challenge(amount="101"),
            "exceeds max_amount",
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
            {"expected_recipients": [RECIPIENT], **TOKEN_CAP},
            make_challenge(amount="1000001"),
            "exceeds max_amount",
            id="recipient-ok-amount-disallowed",
        ),
    ],
)
async def test_charge_policy(
    policy: dict[str, Any],
    challenge: Challenge,
    error: str | None,
) -> None:
    method = make_method(**policy)
    build = AsyncMock(return_value=("0xdeadbeef", CHAIN_ID))
    rpc = AsyncMock(side_effect=AssertionError("unexpected RPC call"))

    # Selection only skips amount-cap violations; recipients are checked before signing.
    assert method.can_handle_challenge(challenge) is (error is None or "recipient" in error)
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
    method = make_method(
        max_atomic_amount=1000,
        max_amount="0.0005",
        max_amount_decimals=6,
        expected_recipients=[RECIPIENT],
    )

    with (
        patch("mpp.methods.tempo.client._rpc_call", AsyncMock()) as rpc,
        patch("pytempo.TempoTransaction.create") as create,
    ):
        with pytest.raises(ValueError, match="exceeds max_atomic_amount"):
            await method.create_credential(make_challenge(amount="1001"))
        with pytest.raises(ValueError, match="exceeds max_amount"):
            await method.create_credential(make_challenge(amount="501"))
        with pytest.raises(ValueError, match="recipient"):
            await method.create_credential(make_challenge(amount="1", recipient=OTHER))

    rpc.assert_not_called()
    create.assert_not_called()


@pytest.mark.parametrize(
    ("max_amount", "cap"),
    [
        pytest.param("1.0000000", 1_000_000, id="trailing-zero"),
        pytest.param("1.500000000", 1_500_000, id="trailing-zeros"),
        pytest.param(Decimal("1.0000000"), 1_000_000, id="decimal-trailing-zero"),
        pytest.param("1E+2", 100_000_000, id="exponent"),
    ],
)
def test_max_amount_trailing_zeros_are_accepted(max_amount: str | Decimal, cap: int) -> None:
    method = make_method(max_amount=max_amount, max_amount_decimals=6)

    assert method.can_handle_challenge(make_challenge(amount=str(cap))) is True
    assert method.can_handle_challenge(make_challenge(amount=str(cap + 1))) is False


@pytest.mark.parametrize(
    ("policy", "amounts", "expected"),
    [
        pytest.param({"max_atomic_amount": 1000}, ["1001", "1000"], 1, id="atomic-over-under"),
        pytest.param(TOKEN_CAP, ["1000001", "999999"], 1, id="token-over-under"),
        pytest.param({"max_atomic_amount": 1000}, ["10", "1001"], 0, id="first-affordable"),
        pytest.param({}, ["1001", "1000"], 0, id="no-cap-first"),
        pytest.param({"expected_recipients": [OTHER]}, ["10", "20"], 0, id="recipients-unused"),
        pytest.param({"max_atomic_amount": 1000}, ["1001", "2000"], None, id="all-over"),
        pytest.param(TOKEN_CAP, ["1000001", "2000000"], None, id="token-all-over"),
    ],
)
def test_challenge_selection_skips_over_cap_offers(
    policy: dict[str, Any], amounts: list[str], expected: int | None
) -> None:
    method = make_method(**policy)
    challenges = [
        make_challenge(amount=amount, challenge_id=f"offer-{index}")
        for index, amount in enumerate(amounts)
    ]
    runtime = PaymentRuntime([method])
    mcp = McpClient(AsyncMock(), methods=[method])
    mcp_challenges = [
        MCPChallenge.from_dict(
            {
                "id": challenge.id,
                "realm": challenge.realm,
                "method": challenge.method,
                "intent": challenge.intent,
                "request": challenge.request,
            }
        )
        for challenge in challenges
    ]

    if expected is None:
        with pytest.raises(ValueError, match="No compatible payment method"):
            runtime.match_challenge(challenges)
        with pytest.raises(ValueError, match="No compatible payment method"):
            mcp._match_challenge(mcp_challenges)
        return
    assert runtime.match_challenge(challenges) == (challenges[expected], method)
    mcp_challenge, mcp_method = mcp._match_challenge(mcp_challenges)
    assert mcp_challenge.id == f"offer-{expected}"
    assert mcp_method is method


@pytest.mark.parametrize(
    ("kwargs", "attribute", "expected"),
    [
        pytest.param({}, "max_atomic_amount", None, id="atomic-unset"),
        pytest.param({}, "max_amount", None, id="token-unset"),
        pytest.param({}, "max_amount_decimals", None, id="token-decimals-unset"),
        pytest.param({}, "expected_recipients", None, id="recipients-unset"),
        pytest.param({}, "decimals", 6, id="decimals-default"),
        pytest.param({"max_atomic_amount": 1000}, "max_atomic_amount", 1000, id="atomic-int"),
        pytest.param(TOKEN_CAP, "max_amount", "1", id="token-str"),
        pytest.param(TOKEN_CAP, "max_amount_decimals", 6, id="token-decimals"),
        pytest.param(
            {"max_amount": Decimal("2"), "max_amount_decimals": 6},
            "max_amount",
            Decimal("2"),
            id="token-decimal",
        ),
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


def tempo_charge(**kwargs: Any) -> TempoMethod:
    return tempo(intents={"charge": ChargeIntent()}, **kwargs)


FINER_THAN_DECIMALS = "has more fractional digits than 6 decimals allow"


@pytest.mark.parametrize(
    "construct",
    [pytest.param(tempo_charge, id="tempo"), pytest.param(TempoMethod, id="TempoMethod")],
)
@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        pytest.param({"max_atomic_amount": -1}, "max_atomic_amount", id="atomic-negative"),
        pytest.param({"max_atomic_amount": True}, "max_atomic_amount", id="atomic-bool"),
        pytest.param({"max_atomic_amount": 1.5}, "max_atomic_amount", id="atomic-float"),
        pytest.param({"max_atomic_amount": "1.5"}, "max_atomic_amount", id="atomic-decimal-str"),
        pytest.param({"max_atomic_amount": "-1"}, "max_atomic_amount", id="atomic-negative-str"),
        pytest.param({"max_atomic_amount": ""}, "max_atomic_amount", id="atomic-empty-str"),
        pytest.param(
            {"max_amount": "1"}, "requires max_amount_decimals", id="token-without-decimals"
        ),
        pytest.param(
            {"max_amount": "1", "decimals": 6},
            "requires max_amount_decimals",
            id="token-ignores-server-decimals",
        ),
        pytest.param(
            {"max_amount": "1", "max_amount_decimals": -1},
            "max_amount_decimals",
            id="token-negative-decimals",
        ),
        pytest.param(
            {"max_amount": "1", "max_amount_decimals": True},
            "max_amount_decimals",
            id="token-bool-decimals",
        ),
        pytest.param(
            {"max_amount": 1, "max_amount_decimals": 6}, "use max_atomic_amount", id="token-int"
        ),
        pytest.param(
            {"max_amount": 0.01, "max_amount_decimals": 6},
            "use max_atomic_amount",
            id="token-float",
        ),
        pytest.param(
            {"max_amount": "abc", "max_amount_decimals": 6},
            "Invalid max_amount",
            id="token-not-number",
        ),
        pytest.param(
            {"max_amount": "-1", "max_amount_decimals": 6}, "non-negative", id="token-negative"
        ),
        pytest.param({"max_amount": "NaN", "max_amount_decimals": 6}, "finite", id="token-nan"),
        pytest.param(
            {"max_amount": Decimal("Infinity"), "max_amount_decimals": 6},
            "finite",
            id="token-infinity",
        ),
        # Rounding must never raise the cap, so extra fractional digits are rejected.
        pytest.param(
            {"max_amount": "1.0000005", "max_amount_decimals": 6},
            FINER_THAN_DECIMALS,
            id="token-finer-than-decimals",
        ),
        pytest.param(
            {"max_amount": "0.0000005", "max_amount_decimals": 6},
            FINER_THAN_DECIMALS,
            id="token-half-base-unit",
        ),
        pytest.param(
            {"max_amount": "0.0000009999999999999999999999999", "max_amount_decimals": 6},
            FINER_THAN_DECIMALS,
            id="token-beyond-decimal-precision",
        ),
        pytest.param(
            {"max_amount": "0.9999999999999999999999999999999", "max_amount_decimals": 6},
            FINER_THAN_DECIMALS,
            id="token-just-below-one",
        ),
    ],
)
def test_invalid_caps_fail_at_construction(
    construct: Callable[..., TempoMethod], kwargs: dict[str, Any], error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        construct(**kwargs)


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        pytest.param({"expected_recipients": RECIPIENT}, "sequence", id="string-recipients"),
        pytest.param({"expected_recipients": ["0x1234"]}, "recipient address", id="short-address"),
        pytest.param({"expected_recipients": [123]}, "recipient address", id="non-string-address"),
    ],
)
def test_tempo_rejects_invalid_expected_recipients(kwargs: dict[str, Any], error: str) -> None:
    with pytest.raises(ValueError, match=error):
        tempo_charge(**kwargs)
