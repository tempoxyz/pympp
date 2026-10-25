"""Ports mppx ``evm/server/Methods.test.ts``."""

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from eth_account import Account

from mpp import Challenge, evm
from mpp.client import Mpp as ClientMppx
from mpp.evm import assets, tokens
from mpp.evm import client as evm_client
from mpp.evm import server as evm_server
from mpp.method import PaymentSuccessHookContext
from mpp.server import Mpp, Request
from mpp.x402._evm import get_address

from ._helpers import SECRET_KEY

RECIPIENT = "0x1234567890123456789012345678901234567890"
REFERENCE = "0x" + "11" * 32
account = Account.from_key("0x" + "11" * 32)


def settler(calls: list[str], name: str) -> evm_server.SettleAuthorization:
    async def settle(_: evm_server.SettleParams) -> evm_server.SettleResult:
        calls.append(name)
        return evm_server.SettleResult(reference=REFERENCE)

    return settle


def recorder(calls: list[str], name: str) -> Callable[[PaymentSuccessHookContext], None]:
    def on_success(_: PaymentSuccessHookContext) -> None:
        calls.append(name)

    return on_success


@pytest.mark.parametrize("chain_id", [1, 8453])
async def test_resolves_ousd_and_usdc_and_settles_only_the_chosen_offer(chain_id: int) -> None:
    # Fixture domains exercise routing; deployment-specific domains come from integrators.
    currencies = [
        assets.from_token(
            token,
            chain_id=chain_id,
            transfer=assets.Eip3009Transfer(name=f"Fixture {index}", version="1"),
        )
        for index, token in enumerate([tokens.OUSD, tokens.USDC])
    ]
    settled: list[str] = []
    succeeded: list[str] = []
    [first] = evm_server.evm(
        chain_id=chain_id,
        currencies=currencies[:1],
        recipient=RECIPIENT,
        settle=settler(settled, "0"),
        on_payment_success=recorder(succeeded, "0"),
    )
    # Distinct settlers exercise method identity, not just the wire name/intent.
    [second] = evm_server.evm(
        chain_id=chain_id,
        currencies=currencies[1:],
        recipient=RECIPIENT,
        settle=settler(settled, "1"),
        on_payment_success=recorder(succeeded, "1"),
    )
    server = Mpp(methods=[[first, second]], secret_key=SECRET_KEY)
    payer = ClientMppx(methods=[evm_client.evm(account=account, currencies=currencies)])

    for route in (server.charge(amount="1"), server.evm.charge(amount="1")):
        offered = await route(Request("GET", "https://example.com/paid"))
        assert offered.status == 402
        challenges = Challenge.from_headers_list(offered.challenge.headers)  # type: ignore[attr-defined]
        assert [c.request["currency"] for c in challenges] == [
            get_address(c.address) for c in currencies
        ]
        for index, challenge in enumerate(challenges):
            credential = await payer.create_credential(
                httpx.Response(
                    402,
                    headers={"WWW-Authenticate": challenge.serialize()},
                    request=httpx.Request("GET", "https://example.com/paid"),
                )
            )
            result = await route(
                Request("GET", "https://example.com/paid", headers={"Authorization": credential})
            )
            assert result.status == 200
            assert settled == [str(index)]
            assert succeeded == [str(index)]
            settled.clear()
            succeeded.clear()


async def noop_settle(_: evm_server.SettleParams) -> evm_server.SettleResult:
    return evm_server.SettleResult(reference=REFERENCE)


def test_preserves_ordering_and_removes_duplicates() -> None:
    methods = evm_server.evm(
        chain_id=8453,
        currencies=[tokens.USDC, tokens.OUSD, tokens.USDC],
        authorization=evm.AuthorizationConfig(name="Fixture", version="1"),
        recipient=RECIPIENT,
        settle=noop_settle,
    )
    assert [m.defaults["currency"] for m in methods] == [  # type: ignore[index]
        get_address(tokens.USDC(8453).address),
        get_address(tokens.OUSD(8453).address),
    ]
    single = evm_server.evm(currencies=[assets.BASE_USDC], recipient=RECIPIENT, settle=noop_settle)
    assert len(single) == 1


def test_filters_unavailable_chains_and_non_usd_tokens() -> None:
    other = assets.Token(addresses={8453: tokens.OUSD(8453).address}, currency="EUR", decimals=6)
    methods = evm_server.evm(
        chain_id=8453,
        currencies=[assets.BASE_SEPOLIA_USDC, other, assets.BASE_USDC],
        recipient=RECIPIENT,
        settle=noop_settle,
    )
    assert len(methods) == 1
    assert methods[0].defaults["currency"] == get_address(tokens.USDC(8453).address)  # type: ignore[index]


@pytest.mark.parametrize(
    ("config", "error"),
    [
        ({"currencies": []}, "No accepted EVM currencies"),
        ({"currencies": [tokens.OUSD], "chain_id": 99999}, "No accepted EVM currencies"),
        ({"currencies": [tokens.OUSD]}, "require `chainId`"),
        ({"currencies": [tokens.OUSD], "chain_id": 8453}, "requires `authorization` metadata"),
    ],
)
def test_rejects_invalid_configuration(config: dict[str, Any], error: str) -> None:
    with pytest.raises(ValueError, match=error):
        evm_server.evm(recipient=RECIPIENT, settle=noop_settle, **config)


def test_retains_the_same_token_address_on_distinct_networks() -> None:
    currencies = [
        assets.define(
            address=tokens.OUSD(8453).address,
            decimals=6,
            network=assets.to_network(chain_id),
            transfer=assets.Eip3009Transfer(name="Fixture", version="1"),
        )
        for chain_id in (1, 8453)
    ]
    methods = evm_server.evm(currencies=currencies, recipient=RECIPIENT, settle=noop_settle)
    assert [m.defaults["chainId"] for m in methods] == [1, 8453]  # type: ignore[index]
