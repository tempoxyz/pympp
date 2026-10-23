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
from mpp.methods.tempo import (
    CHAIN_ID,
    PATH_USD,
    TESTNET_CHAIN_ID,
    USDC,
    ChargeIntent,
    TempoAccount,
    tempo,
)
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
    currency: str = PATH_USD,
    chain_id: int | str | None = None,
) -> Challenge:
    request: dict[str, Any] = {"amount": amount, "currency": currency, "recipient": recipient}
    method_details: dict[str, Any] = {}
    if splits is not None:
        method_details["splits"] = splits
    if chain_id is not None:
        method_details["chainId"] = chain_id
    if method_details:
        request["methodDetails"] = method_details
    return Challenge(
        id=challenge_id,
        method="tempo",
        intent="charge",
        realm="api.example.com",
        request=request,
    )


def make_method(**policy: Any) -> TempoMethod:
    """Build a client method, pinned to pathUSD unless the policy pins a currency."""
    if "currency" not in policy and "currencies" not in policy:
        policy["currencies"] = [PATH_USD]
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
        # currency pin required by the caps
        pytest.param(
            {"max_atomic_amount": 1000},
            make_challenge(currency=USDC),
            "not a currency the client pinned",
            id="cap-other-currency",
        ),
        pytest.param(
            TOKEN_CAP,
            make_challenge(amount="1", currency=USDC),
            "not a currency the client pinned",
            id="token-cap-other-currency",
        ),
        pytest.param(
            {"max_atomic_amount": 1000, "currency": USDC},
            make_challenge(currency=swap_case(USDC)),
            None,
            id="cap-currency-pin-case-insensitive",
        ),
        pytest.param({}, make_challenge(currency=USDC), None, id="no-cap-any-currency"),
        # chain pin (default tempo() pins mainnet)
        pytest.param({}, make_challenge(chain_id=CHAIN_ID), None, id="chain-pinned"),
        pytest.param(
            {},
            make_challenge(chain_id=TESTNET_CHAIN_ID),
            f"client is restricted to {CHAIN_ID}",
            id="chain-mismatch",
        ),
        pytest.param(
            {"chain_id": TESTNET_CHAIN_ID},
            make_challenge(chain_id=CHAIN_ID),
            f"client is restricted to {TESTNET_CHAIN_ID}",
            id="explicit-chain-mismatch",
        ),
        pytest.param({}, make_challenge(chain_id="abc"), None, id="chain-not-numeric"),
        # allowed_chain_ids
        pytest.param(
            {"allowed_chain_ids": [CHAIN_ID]},
            make_challenge(chain_id=CHAIN_ID),
            None,
            id="allowed-chain",
        ),
        pytest.param(
            {"allowed_chain_ids": [CHAIN_ID, TESTNET_CHAIN_ID]},
            make_challenge(),
            None,
            id="allowed-chain-from-client-pin",
        ),
        pytest.param(
            {"chain_id": TESTNET_CHAIN_ID, "allowed_chain_ids": [CHAIN_ID]},
            make_challenge(),
            f"Chain ID not allowed: {TESTNET_CHAIN_ID}",
            id="client-pin-not-allowed",
        ),
        pytest.param(
            {"chain_id": TESTNET_CHAIN_ID, "allowed_chain_ids": [CHAIN_ID]},
            make_challenge(chain_id=TESTNET_CHAIN_ID),
            f"Chain ID not allowed: {TESTNET_CHAIN_ID}",
            id="challenge-chain-not-allowed",
        ),
        pytest.param(
            {"allowed_chain_ids": [TESTNET_CHAIN_ID]},
            make_challenge(chain_id=CHAIN_ID),
            "Chain ID not allowed",
            id="pinned-chain-outside-allowlist",
        ),
        pytest.param(
            {"allowed_chain_ids": []},
            make_challenge(chain_id=CHAIN_ID),
            "Chain ID not allowed",
            id="empty-chain-allowlist",
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

    assert method.can_handle_challenge(challenge) is (error is None)
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


OVER = {"amount": "1001"}
UNDER = {"amount": "1000"}


@pytest.mark.parametrize(
    ("policy", "offers", "expected"),
    [
        pytest.param({"max_atomic_amount": 1000}, [OVER, UNDER], 1, id="atomic-over-under"),
        pytest.param(
            TOKEN_CAP, [{"amount": "1000001"}, {"amount": "999999"}], 1, id="token-over-under"
        ),
        pytest.param({"max_atomic_amount": 1000}, [UNDER, OVER], 0, id="first-affordable"),
        pytest.param({}, [OVER, UNDER], 0, id="no-cap-first"),
        pytest.param(
            {"expected_recipients": [RECIPIENT]},
            [{"recipient": OTHER}, {}],
            1,
            id="disallowed-recipient-then-allowed",
        ),
        pytest.param(
            {"expected_recipients": [RECIPIENT]},
            [{"splits": [{"amount": "1", "recipient": OTHER}]}, {}],
            1,
            id="disallowed-split-then-allowed",
        ),
        pytest.param(
            {"max_atomic_amount": 1000, "currencies": [PATH_USD]},
            [{"amount": "10", "currency": USDC}, {"amount": "10"}],
            1,
            id="wrong-then-right-currency",
        ),
        pytest.param(
            {"max_atomic_amount": 1000},
            [{"amount": "10", "currency": USDC}],
            None,
            id="all-wrong-currency",
        ),
        pytest.param(
            {},
            [{"chain_id": TESTNET_CHAIN_ID}, {"chain_id": CHAIN_ID}],
            1,
            id="wrong-then-right-chain",
        ),
        pytest.param(
            {"chain_id": TESTNET_CHAIN_ID},
            [{"chain_id": CHAIN_ID}, {"chain_id": TESTNET_CHAIN_ID}],
            1,
            id="explicit-chain-wrong-then-right",
        ),
        pytest.param({"max_atomic_amount": 1000}, [OVER, {"amount": "2000"}], None, id="all-over"),
        pytest.param(
            {},
            [{"chain_id": TESTNET_CHAIN_ID}, {"chain_id": 1}],
            None,
            id="all-wrong-chain",
        ),
        pytest.param(
            TOKEN_CAP, [{"amount": "1000001"}, {"amount": "2000000"}], None, id="token-all-over"
        ),
        pytest.param(
            {"expected_recipients": [RECIPIENT]},
            [{"recipient": OTHER}],
            None,
            id="all-recipients-disallowed",
        ),
    ],
)
def test_challenge_selection_skips_offers_outside_policy(
    policy: dict[str, Any], offers: list[dict[str, Any]], expected: int | None
) -> None:
    method = make_method(**policy)
    challenges = [
        make_challenge(challenge_id=f"offer-{index}", **offer) for index, offer in enumerate(offers)
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
    ("cached_chain_id", "expected"),
    [
        pytest.param(TESTNET_CHAIN_ID, 1, id="cached-rpc-chain-skips-wrong-chain"),
        pytest.param(None, 0, id="uncached-rpc-chain-left-to-pre-sign-guard"),
    ],
)
async def test_selection_uses_cached_rpc_chain_pin(
    cached_chain_id: int | None, expected: int
) -> None:
    method = make_method(rpc_url="https://rpc.custom")
    if cached_chain_id is not None:
        method._cached_chain_ids["https://rpc.custom"] = cached_chain_id
    challenges = [
        make_challenge(chain_id=CHAIN_ID, challenge_id="offer-0"),
        make_challenge(chain_id=TESTNET_CHAIN_ID, challenge_id="offer-1"),
    ]

    assert PaymentRuntime([method]).match_challenge(challenges) == (challenges[expected], method)
    method._cached_chain_ids["https://rpc.custom"] = TESTNET_CHAIN_ID
    build = AsyncMock(return_value=("0xdeadbeef", TESTNET_CHAIN_ID))
    with patch.object(method, "_build_tempo_transfer", build):
        with pytest.raises(ValueError, match=f"client is restricted to {TESTNET_CHAIN_ID}"):
            await method.create_credential(challenges[0])
    build.assert_not_awaited()


@pytest.mark.parametrize(
    "construct",
    [
        pytest.param(lambda **kwargs: tempo_charge(**kwargs), id="tempo"),
        pytest.param(TempoMethod, id="TempoMethod"),
    ],
)
@pytest.mark.parametrize(
    ("caps", "pin", "error"),
    [
        pytest.param({"max_atomic_amount": 1000}, {}, "require a currency pin", id="atomic-no-pin"),
        pytest.param(TOKEN_CAP, {}, "require a currency pin", id="token-no-pin"),
        pytest.param({"max_atomic_amount": 1000}, {"currency": PATH_USD}, None, id="currency"),
        pytest.param(TOKEN_CAP, {"currencies": [PATH_USD, USDC]}, None, id="currencies"),
        pytest.param({}, {}, None, id="no-cap-no-pin"),
    ],
)
def test_caps_require_currency_pin(
    construct: Callable[..., TempoMethod],
    caps: dict[str, Any],
    pin: dict[str, Any],
    error: str | None,
) -> None:
    if construct is TempoMethod and "currencies" in pin:
        pin = {"currencies": tuple(pin["currencies"])}
    if error is None:
        construct(**caps, **pin)
        return
    with pytest.raises(ValueError, match=error):
        construct(**caps, **pin)


async def test_direct_method_cap_skips_and_rejects_other_currency() -> None:
    method = TempoMethod(
        account=TempoAccount.from_key(TEST_PRIVATE_KEY),
        currencies=(PATH_USD,),
        max_atomic_amount=1000,
    )
    method._intents = {"charge": ChargeIntent()}
    challenges = [
        make_challenge(currency=USDC, challenge_id="offer-0"),
        make_challenge(challenge_id="offer-1"),
    ]
    build = AsyncMock(return_value=("0xdeadbeef", CHAIN_ID))

    assert PaymentRuntime([method]).match_challenge(challenges) == (challenges[1], method)
    with patch.object(method, "_build_tempo_transfer", build):
        with pytest.raises(ValueError, match="not a currency the client pinned"):
            await method.create_credential(challenges[0])
    build.assert_not_awaited()


async def test_caps_changed_after_construction_are_enforced() -> None:
    method = make_method()
    challenge = make_challenge(amount="1001")
    build = AsyncMock(return_value=("0xdeadbeef", CHAIN_ID))
    assert method.can_handle_challenge(challenge) is True

    method.max_atomic_amount = 1000
    assert method.can_handle_challenge(challenge) is False

    method.max_atomic_amount = None
    method.max_amount, method.max_amount_decimals = "0.001", 6
    assert method.can_handle_challenge(challenge) is False
    assert method.can_handle_challenge(make_challenge(amount="1000")) is True

    method.max_amount_decimals = None
    assert method.can_handle_challenge(make_challenge(amount="1")) is False
    with patch.object(method, "_build_tempo_transfer", build):
        with pytest.raises(ValueError, match="requires max_amount_decimals"):
            await method.create_credential(make_challenge(amount="1"))

    unpinned = tempo(account=TempoAccount.from_key(TEST_PRIVATE_KEY), intents={})
    unpinned.max_atomic_amount = 1000
    assert unpinned.can_handle_challenge(make_challenge(amount="1")) is False
    with patch.object(unpinned, "_build_tempo_transfer", build):
        with pytest.raises(ValueError, match="require a currency pin"):
            await unpinned.create_credential(make_challenge(amount="1"))
    build.assert_not_awaited()


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
    method = make_method(**kwargs)

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


def test_allowed_chain_ids_rejects_unknown_chain_only_when_empty() -> None:
    method = make_method(allowed_chain_ids=[CHAIN_ID])
    method._check_allowed_chain_id(None)
    with pytest.raises(ValueError, match="Chain ID not allowed: unknown"):
        make_method(allowed_chain_ids=[])._check_allowed_chain_id(None)


@pytest.mark.parametrize("value", ["4217", [True], ["4217"]])
def test_allowed_chain_ids_rejects_invalid_values(value: Any) -> None:
    with pytest.raises(ValueError, match="allowed_chain_ids|Invalid Tempo chain ID"):
        make_method(allowed_chain_ids=value)
