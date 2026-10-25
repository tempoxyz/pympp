from __future__ import annotations

import json
import re
from typing import Any

import httpx
import pytest

from mpp import store as _store
from mpp.challenge import Challenge
from mpp.method import VerifyContext
from mpp.receipt import Receipt
from mpp.server import Mpp, Request
from mpp.tempo import server as tempo
from mpp.tempo._internal.rpc import RpcClient
from mpp.tempo.assets import OUSD_ADDRESS, PATH_USD_ADDRESS, USDC_ADDRESS, Token

pytestmark = pytest.mark.filterwarnings("ignore:tempo.charge\\(\\) has no `store`:UserWarning")

RECIPIENT = "0x1234567890123456789012345678901234567890"
SECRET_KEY = "test-secret-key-test-secret-key-32"
URL = "https://example.com/paid"


async def _never(_: VerifyContext[Any]) -> Receipt:
    raise NotImplementedError


async def offers(handler: Any) -> list[Challenge]:
    result = await handler(Request(method="GET", url=URL))
    assert result.status == 402
    return Challenge.deserialize_list(result.challenge.headers["www-authenticate"])


def _unexpected_rpc(request: httpx.Request) -> httpx.Response:
    # Unlike viem clients, an `RpcClient` does not know its chain statically: the deprecated
    # single-`currency` path (no chain configured) asks the node once via `eth_chainId`.
    body = json.loads(request.content)
    if body["method"] == "eth_chainId":
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": "0x1079"})
    raise AssertionError(f"Unexpected RPC call: {request.content!r}")


RPC = RpcClient(
    "https://rpc.example.com",
    http=httpx.AsyncClient(transport=httpx.MockTransport(_unexpected_rpc)),
)


def config(**overrides: Any) -> dict[str, Any]:
    return {
        "recipient": RECIPIENT,
        "get_client": lambda _: RPC,
        "store": _store.memory(),
        **overrides,
    }


class TestCommonCurrencyOffers:
    def test_common_alias_and_omitted_parameters(self) -> None:
        assert tempo.common is tempo.tempo
        assert [(m.intent, m.defaults["currency"]) for m in tempo.tempo(store=_store.memory())] == [
            ("charge", OUSD_ADDRESS),
            ("charge", USDC_ADDRESS),
        ]

    @pytest.mark.parametrize(
        ("parameters", "currencies"),
        [
            ({}, [OUSD_ADDRESS, USDC_ADDRESS]),
            ({"currency": USDC_ADDRESS}, [USDC_ADDRESS]),
            ({"currencies": [USDC_ADDRESS, OUSD_ADDRESS]}, [USDC_ADDRESS, OUSD_ADDRESS]),
            ({"currencies": [OUSD_ADDRESS, OUSD_ADDRESS.lower()]}, [OUSD_ADDRESS]),
        ],
    )
    async def test_advertises_charge_offers(
        self,
        parameters: dict[str, Any],
        currencies: list[str],
    ) -> None:
        mppx = Mpp(methods=[tempo.common(**config(**parameters))], secret_key=SECRET_KEY)
        charges = await offers(mppx.charge(amount="1.25"))
        assert [c.request["currency"] for c in charges] == currencies
        assert len({c.id for c in charges}) == len(currencies)
        for challenge in charges:
            assert challenge.request["amount"] == "1250000"
            assert challenge.request["recipient"] == RECIPIENT
            assert challenge.request["methodDetails"]["chainId"] == 4217

    @pytest.mark.parametrize("parameters", [{"testnet": True}, {"chain_id": 42431}])
    async def test_testnet_defaults_offer_ousd_then_path_usd(
        self, parameters: dict[str, Any]
    ) -> None:
        mppx = Mpp(methods=[tempo.common(**config(**parameters))], secret_key=SECRET_KEY)
        challenges = await offers(mppx.charge(amount="1"))
        assert [c.request["currency"] for c in challenges] == [OUSD_ADDRESS, PATH_USD_ADDRESS]
        for challenge in challenges:
            assert challenge.request["amount"] == "1000000"
            assert challenge.request["methodDetails"]["chainId"] == 42431

    async def test_token_definitions_normalize_amounts_per_token(self) -> None:
        token = Token(addresses={4217: OUSD_ADDRESS}, currency="USD", decimals=8)
        mppx = Mpp(
            methods=[tempo.common(**config(currencies=[token, USDC_ADDRESS]))],
            secret_key=SECRET_KEY,
        )
        challenges = await offers(mppx.charge(amount="1.25"))
        assert [(c.request["currency"], c.request["amount"]) for c in challenges] == [
            (OUSD_ADDRESS, "125000000"),
            (USDC_ADDRESS, "1250000"),
        ]

    def test_keeps_explicit_single_currency(self) -> None:
        (charge,) = tempo.common(**config(currency=USDC_ADDRESS))
        assert charge.intent == "charge"
        assert charge.defaults["currency"] == USDC_ADDRESS

    def test_rejects_conflicting_currency_options(self) -> None:
        with pytest.raises(
            ValueError, match=re.escape("Specify either `currency` or `currencies`, not both.")
        ):
            tempo.common(**config(currency=USDC_ADDRESS, currencies=[OUSD_ADDRESS]))

    def test_rejects_empty_allowed_fee_tokens(self) -> None:
        with pytest.raises(ValueError, match="`allowedFeeTokens` must contain at least one"):
            tempo.common(**config(allowed_fee_tokens=[]))

    def test_rejects_unknown_keyword_arguments(self) -> None:
        with pytest.raises(TypeError, match="unexpected keyword argument"):
            tempo.common(**config(not_an_option=True))


class TestIndividualChargeOffers:
    @pytest.mark.parametrize(
        ("parameters", "expected", "chain_id"),
        [
            ({}, [OUSD_ADDRESS, USDC_ADDRESS], 4217),
            ({"testnet": True}, [OUSD_ADDRESS, PATH_USD_ADDRESS], 42431),
            ({"chain_id": 42431}, [OUSD_ADDRESS, PATH_USD_ADDRESS], 42431),
            ({"currencies": [USDC_ADDRESS, OUSD_ADDRESS]}, [USDC_ADDRESS, OUSD_ADDRESS], 4217),
            ({"currency": USDC_ADDRESS}, [USDC_ADDRESS], 4217),
            ({"currencies": [OUSD_ADDRESS]}, [OUSD_ADDRESS], 4217),
        ],
    )
    async def test_charge_offers(
        self, parameters: dict[str, Any], expected: list[str], chain_id: int
    ) -> None:
        offered = tempo.charge(**config(**parameters))
        assert [m.intent for m in offered] == ["charge"] * len(expected)
        mppx = Mpp(methods=[offered], secret_key=SECRET_KEY)
        challenges = await offers(mppx.charge(amount="1.25"))
        assert [c.request["currency"].lower() for c in challenges] == [e.lower() for e in expected]
        assert len({c.id for c in challenges}) == len(expected)
        for challenge in challenges:
            assert challenge.request["amount"] == "1250000"
            assert challenge.request["methodDetails"]["chainId"] == chain_id

    def test_rejects_conflicting_or_empty_lists(self) -> None:
        with pytest.raises(ValueError, match="Specify either"):
            tempo.charge(**config(currency=USDC_ADDRESS, currencies=[OUSD_ADDRESS]))
        with pytest.raises(ValueError, match="No accepted USD currencies"):
            tempo.charge(**config(currencies=[]))


@pytest.mark.parametrize("with_store", [False, True])
async def test_proof_replay_preserves_explicit_store_policy(with_store: bool) -> None:
    from mpp.credential import Credential
    from mpp.tempo import proof
    from mpp.tempo._internal.account import secp256k1_account

    account = secp256k1_account("0x" + "01" * 32)
    parameters = config()
    if not with_store:
        parameters.pop("store")
    server = Mpp(methods=[tempo.common(**parameters)], secret_key=SECRET_KEY)
    handler = server.charge(amount="0")
    for challenge in await offers(handler):
        signature = account.sign_typed_data(
            proof.typed_data(
                account=account.address,
                chain_id=4217,
                challenge_id=challenge.id,
                realm=challenge.realm,
            )
        )
        authorization = Credential(
            challenge=challenge,
            payload={"signature": signature, "type": "proof"},
            source=f"did:pkh:eip155:4217:{account.address}",
        ).serialize()

        async def pay(value: str = authorization) -> int:
            result = await handler(
                Request(method="GET", url="https://example.com", headers={"Authorization": value})
            )
            return result.status

        assert await pay() == 200
        assert await pay() == (402 if with_store else 200)


def test_client_group() -> None:
    from mpp.tempo import client as tempo_client
    from mpp.tempo._internal.account import secp256k1_account

    group = tempo_client.tempo(
        account=secp256k1_account("0x" + "01" * 32),
        expected_chain_id=42431,
        currencies=[PATH_USD_ADDRESS],
        decimals=6,
        max_amount="1",
    )
    assert [m.key for m in group] == ["tempo/charge"]
    assert tempo_client.common is tempo_client.tempo
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        tempo_client.tempo(not_an_option=True)
