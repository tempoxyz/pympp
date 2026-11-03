"""Client-side spending policy for Tempo sessions (port of mppx's ``session spending policy``
tests): ``currencies``, ``max_amount``, ``max_atomic_amount`` and ``expected_recipients`` skip
offers during challenge selection and reject them before signing or topping up, while explicit
closes stay available for any offer."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import Challenge, NoMethodFoundError
from mpp.client.transport import PaymentTransport
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._protocol import ESCROW_ADDRESS, ZERO_ADDRESS, ChannelDescriptor
from mpp.methods.tempo.session.client import ChannelEntry, SessionMethod, session
from mpp.methods.tempo.session.client._state import SessionContext
from mpp.runtime import CredentialParams

ACCOUNT = TempoAccount.from_key("0x" + "ab" * 32)
PAYEE = "0x" + "11" * 20
TOKEN = "0x20c0000000000000000000000000000000000000"
OTHER = "0x0000000000000000000000000000000000000009"
CHAIN_ID = 4217
URL = "http://api.test/paid"


def swap_case(address: str) -> str:
    """Return the address with its hex digits in the opposite case."""
    return "0x" + address[2:].swapcase()


def make_challenge(*, amount: str = "100", recipient: str | None = PAYEE) -> Challenge:
    request: dict[str, Any] = {
        "amount": amount,
        "currency": TOKEN,
        "unitType": "request",
        "methodDetails": {
            "sessionProtocol": "v2",
            "escrowContract": ESCROW_ADDRESS,
            "chainId": CHAIN_ID,
        },
    }
    if recipient is not None:
        request["recipient"] = recipient
    return Challenge(
        id=os.urandom(8).hex(),
        method="tempo",
        intent="session",
        request=request,
        realm="api.test",
        expires=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    )


DESCRIPTOR = ChannelDescriptor(
    payer=ACCOUNT.address,
    payee=PAYEE,
    operator=ZERO_ADDRESS,
    token=TOKEN,
    salt="0x" + "33" * 32,
    authorized_signer=ACCOUNT.address,
    expiring_nonce_hash="0x" + "44" * 32,
)
CHANNEL_ID = compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID)
VOUCHER = SessionContext(action="voucher", descriptor=DESCRIPTOR, cumulative_amount_raw="100")
CLOSE = SessionContext(
    action="close", channel_id=CHANNEL_ID, descriptor=DESCRIPTOR, cumulative_amount_raw="100"
)


def payload_of(authorization: str) -> dict[str, Any]:
    token = authorization.removeprefix("Payment ")
    decoded = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    return decoded["payload"]


def spy_resolve(monkeypatch: pytest.MonkeyPatch, method: SessionMethod) -> list[Challenge]:
    """Record calls to the method's challenge resolution, the first step after the policy."""
    calls: list[Challenge] = []
    resolve = method.resolve

    async def recording(challenge: Challenge) -> Any:
        calls.append(challenge)
        return await resolve(challenge)

    monkeypatch.setattr(method, "resolve", recording)
    return calls


def spy_signing(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Record every hash the payer signs."""
    calls: list[Any] = []
    sign = TempoAccount.sign_hash

    def recording(self: TempoAccount, *args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return sign(self, *args, **kwargs)

    monkeypatch.setattr(TempoAccount, "sign_hash", recording)
    return calls


@pytest.mark.parametrize(
    ("policy", "error"),
    [
        pytest.param({"currencies": [TOKEN]}, None, id="allowed currency"),
        pytest.param(
            {"currencies": [swap_case(TOKEN)]}, None, id="allowed currency in another case"
        ),
        pytest.param(
            {"currencies": [OTHER]},
            "Tempo session currency is not allowed",
            id="disallowed currency",
        ),
        pytest.param(
            {"currencies": []}, "Tempo session currency is not allowed", id="empty currencies"
        ),
        pytest.param(
            {"currencies": [TOKEN], "max_atomic_amount": "100"}, None, id="atomic equal to cap"
        ),
        pytest.param(
            {"currencies": [TOKEN], "max_atomic_amount": 99},
            "Tempo session amount exceeds max_atomic_amount.",
            id="atomic above cap",
        ),
        pytest.param(
            {"currencies": [TOKEN], "max_amount": "1", "max_amount_decimals": 2},
            None,
            id="display equal to cap",
        ),
        pytest.param(
            {"currencies": [TOKEN], "max_amount": "0.99", "max_amount_decimals": 2},
            "Tempo session amount exceeds max_amount.",
            id="display above cap",
        ),
    ],
)
async def test_applies_currency_and_amount_policy(
    monkeypatch: pytest.MonkeyPatch, policy: dict[str, Any], error: str | None
) -> None:
    method = SessionMethod(account=ACCOUNT, **policy)
    resolves = spy_resolve(monkeypatch, method)
    challenge = make_challenge()

    assert method.client_method().can_handle_challenge is not None
    assert method.can_handle_challenge(challenge) is (error is None)
    if error is None:
        credential = await method.create_session_credential(challenge, VOUCHER)
        assert payload_of(credential)["action"] == "voucher"
        return
    with pytest.raises(ValueError, match=error):
        await method.create_session_credential(challenge, VOUCHER)
    assert resolves == []


@pytest.mark.parametrize("action", ["automatic", "open", "topUp", "voucher", "recover"])
async def test_rejects_an_over_cap_offer_before_signing(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    method = SessionMethod(account=ACCOUNT, currencies=[TOKEN], max_atomic_amount="99")
    resolves = spy_resolve(monkeypatch, method)
    signatures = spy_signing(monkeypatch)
    context = (
        None
        if action == "automatic"
        else SessionContext(descriptor=DESCRIPTOR)
        if action == "recover"
        else SessionContext(
            action=action,  # pyright: ignore[reportArgumentType]
            descriptor=DESCRIPTOR,
            transaction="0x1234",
            cumulative_amount_raw="100",
        )
    )
    with pytest.raises(ValueError, match="Tempo session amount exceeds max_atomic_amount."):
        await method.create_credential(
            CredentialParams(challenge=make_challenge(), context=context)
        )
    assert resolves == [] and signatures == []


@pytest.mark.parametrize(
    ("policy", "error"),
    [
        pytest.param(
            {"currencies": [TOKEN], "max_atomic_amount": "99"},
            "Tempo session amount exceeds max_atomic_amount.",
            id="amount",
        ),
        pytest.param(
            {"expected_recipients": [OTHER]}, "Unexpected session recipient", id="recipient"
        ),
    ],
)
async def test_rejects_an_out_of_policy_offer_before_topping_up(
    policy: dict[str, Any], error: str
) -> None:
    method = SessionMethod(account=ACCOUNT, **policy)
    sent: list[httpx.Request] = []

    async def send(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(204)

    channel = ChannelEntry(
        channel_id=CHANNEL_ID,
        cumulative_amount=100,
        deposit=100,
        descriptor=DESCRIPTOR,
        escrow=ESCROW_ADDRESS,
        chain_id=CHAIN_ID,
        opened=True,
    )
    with pytest.raises(ValueError, match=error):
        await method.top_up_channel_if_needed(
            challenge=make_challenge(),
            channel=channel,
            deposit=100,
            required_cumulative=300,
            url=URL,
            send=send,
        )
    assert sent == []


@pytest.mark.parametrize(
    "policy",
    [
        pytest.param({"currencies": [TOKEN], "max_atomic_amount": "99"}, id="amount"),
        pytest.param({"expected_recipients": [OTHER]}, id="recipient"),
    ],
)
async def test_does_not_pay_an_out_of_policy_offer_through_the_client(
    policy: dict[str, Any],
) -> None:
    challenge = make_challenge()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            402, headers={"WWW-Authenticate": challenge.to_www_authenticate("api.test")}
        )

    transport = PaymentTransport(
        methods=[session(account=ACCOUNT, **policy)], inner=httpx.MockTransport(handler)
    )
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(NoMethodFoundError, match="No method found"):
            await client.get(URL)
    assert len(requests) == 1


@pytest.mark.parametrize(
    "policy",
    [
        pytest.param({"currencies": [OTHER]}, id="currency"),
        pytest.param({"currencies": [TOKEN], "max_atomic_amount": "99"}, id="amount"),
        pytest.param({"expected_recipients": [OTHER]}, id="recipient"),
    ],
)
async def test_still_signs_explicit_closes_for_offers_outside_the_policy(
    policy: dict[str, Any],
) -> None:
    method = SessionMethod(account=ACCOUNT, **policy)
    challenge = make_challenge()
    assert not method.can_handle_challenge(challenge)
    close = payload_of(await method.create_session_credential(challenge, CLOSE))
    assert close["action"] == "close" and close["closeSignature"].startswith("0x")
    with pytest.raises(ValueError):
        await method.create_session_credential(challenge, VOUCHER)


@pytest.mark.parametrize(
    ("recipients", "recipient", "error"),
    [
        pytest.param([PAYEE], PAYEE, None, id="allowed recipient"),
        pytest.param([swap_case(PAYEE)], PAYEE, None, id="allowed recipient in another case"),
        pytest.param([OTHER], PAYEE, "Unexpected session recipient", id="unexpected recipient"),
        pytest.param([PAYEE], None, "Unexpected session recipient", id="missing recipient"),
        pytest.param([], PAYEE, "Unexpected session recipient", id="empty recipients"),
    ],
)
async def test_applies_expected_recipients(
    monkeypatch: pytest.MonkeyPatch,
    recipients: list[str],
    recipient: str | None,
    error: str | None,
) -> None:
    method = SessionMethod(account=ACCOUNT, expected_recipients=recipients)
    resolves = spy_resolve(monkeypatch, method)
    signatures = spy_signing(monkeypatch)
    challenge = make_challenge(recipient=recipient)

    assert method.can_handle_challenge(challenge) is (error is None)
    if error is None:
        credential = await method.create_session_credential(challenge, VOUCHER)
        assert payload_of(credential)["action"] == "voucher"
        return
    with pytest.raises(ValueError, match=error):
        await method.create_session_credential(challenge, VOUCHER)
    assert resolves == [] and signatures == []


@pytest.mark.parametrize(
    ("policy", "error"),
    [
        pytest.param(
            {"max_atomic_amount": "1"},
            "max_amount and max_atomic_amount require currencies",
            id="atomic cap without currencies",
        ),
        pytest.param(
            {"max_amount": "1", "max_amount_decimals": 6},
            "max_amount and max_atomic_amount require currencies",
            id="display cap without currencies",
        ),
        pytest.param(
            {"currencies": [TOKEN], "max_amount": "1"},
            "max_amount requires max_amount_decimals",
            id="display cap without decimals",
        ),
        pytest.param(
            {"currencies": [TOKEN], "max_amount": "0.001", "max_amount_decimals": 2},
            "Tempo session max_amount 0.001 has more fractional digits than 2 decimals allow.",
            id="display cap with too many fractional digits",
        ),
        pytest.param(
            {"currencies": [TOKEN], "max_atomic_amount": "-1"},
            "max_atomic_amount must be a non-negative integer",
            id="negative atomic cap",
        ),
        pytest.param(
            {"currencies": ["0x1234"]}, "Invalid Tempo currency address", id="bad currency"
        ),
        pytest.param(
            {"expected_recipients": PAYEE},
            "must be a sequence of addresses",
            id="recipient string",
        ),
    ],
)
def test_rejects_invalid_configuration(policy: dict[str, Any], error: str) -> None:
    with pytest.raises(ValueError, match=error):
        session(account=ACCOUNT, **policy)


def test_accepts_trailing_zeros_in_a_display_cap() -> None:
    method = SessionMethod(
        account=ACCOUNT, currencies=[TOKEN], max_amount="1.000", max_amount_decimals=2
    )
    assert method.can_handle_challenge(make_challenge(amount="100"))
    assert not method.can_handle_challenge(make_challenge(amount="101"))


async def test_rejects_a_non_integer_amount_under_a_cap() -> None:
    method = SessionMethod(account=ACCOUNT, currencies=[TOKEN], max_atomic_amount="100")
    with pytest.raises(ValueError, match="Challenge amount must be an integer in base units"):
        await method.create_session_credential(make_challenge(amount="1.5"), VOUCHER)
