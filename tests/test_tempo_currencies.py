"""Ordered Tempo currency offers: OUSD-first server defaults and ``currencies=``."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import rlp

import mpp.methods.tempo as tempo_exports
from mpp import Challenge, Credential, Receipt
from mpp.methods.tempo import (
    CHAIN_ID,
    MACH,
    OUSD,
    PATH_USD,
    TESTNET_CHAIN_ID,
    USDC,
    TempoAccount,
    default_currencies_for_chain,
    default_currency_for_chain,
    fee_tokens_for_chain,
    tempo,
)
from mpp.methods.tempo._defaults import (
    DEFAULT_ACCEPTED_CURRENCIES,
    DEFAULT_CURRENCIES,
    FEE_TOKENS,
)
from mpp.methods.tempo.client import TempoMethod
from mpp.methods.tempo.fee_payer_policy import DEFAULT_POLICY, POLICY_BY_CHAIN_ID, Policy
from mpp.methods.tempo.intents import (
    TRANSFER_WITH_MEMO_TOPIC,
    ChargeIntent,
    _raw_transaction_hash,
)
from mpp.methods.tempo.schemas import ChargeRequest
from mpp.runtime import PaymentRuntime
from mpp.server import ComposedChallenges, Intent, Mpp, VerifiableIntent
from mpp.server.intent import VerificationError
from tests import MockRequest, make_bound_credential

REALM = "api.example.com"
SECRET = "test-secret"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
OTHER_TOKEN = "0x20c0000000000000000000000000000000000001"
TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def swap_case(address: str) -> str:
    """Return the address with its hex digits in the opposite case."""
    return "0x" + address[2:].swapcase()


class RecordingIntent:
    """Charge intent that records the offer request it verified."""

    name = "charge"

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    async def verify(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        del credential
        self.requests.append(request)
        return Receipt.success(f"paid-{request['currency']}")


class OtherMethod:
    """Minimal second payment method for multi-method composition."""

    name = "other"
    currency = "usd"
    recipient = "acct_123"
    decimals = 2

    def __init__(self) -> None:
        self.intent = RecordingIntent()
        self.intents: Mapping[str, Intent | VerifiableIntent] = {"charge": self.intent}

    async def create_credential(self, challenge: Challenge) -> Credential:
        raise NotImplementedError


def server_method(**kwargs: Any) -> tuple[TempoMethod, RecordingIntent]:
    intent = RecordingIntent()
    method = tempo(intents={"charge": intent}, recipient=RECIPIENT, **kwargs)
    return method, intent


def create_server(method: Any = None, **kwargs: Any) -> Mpp:
    return Mpp.create(method=method, realm=REALM, secret_key=SECRET, **kwargs)


def challenges_of(result: Any) -> tuple[Challenge, ...]:
    if isinstance(result, Challenge):
        return (result,)
    assert isinstance(result, ComposedChallenges), result
    return result.challenges


def currencies_of(result: Any) -> list[str]:
    return [challenge.request["currency"] for challenge in challenges_of(result)]


def pay_with(challenge: Challenge) -> str:
    return Credential(challenge=challenge.to_echo(), payload={}).to_authorization()


def response_challenges(response: Any) -> list[Challenge]:
    if hasattr(response, "raw_headers"):
        values = [
            value.decode()
            for name, value in response.raw_headers
            if name.lower() == b"www-authenticate"
        ]
    else:
        raw = response["headers"]["WWW-Authenticate"]
        values = [raw] if isinstance(raw, str) else raw
    return [Challenge.from_www_authenticate(value) for value in values]


# ──────────────────────────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────────────────────────


class TestDefaults:
    def test_ousd_address_and_exports(self) -> None:
        assert OUSD == "0x20c0000000000000000000006a37DA5C996874BE"
        assert tempo_exports.OUSD == OUSD
        assert tempo_exports.default_currencies_for_chain is default_currencies_for_chain

    def test_mainnet_defaults_are_ousd_then_usdc(self) -> None:
        assert USDC == "0x20C000000000000000000000b9537d11c60E8b50"
        assert default_currencies_for_chain(CHAIN_ID) == (OUSD, USDC)
        assert default_currencies_for_chain(4217) == (OUSD, USDC)

    def test_moderato_defaults_are_ousd_then_path_usd(self) -> None:
        assert default_currencies_for_chain(TESTNET_CHAIN_ID) == (OUSD, PATH_USD)
        assert default_currencies_for_chain(42431) == (OUSD, PATH_USD)

    @pytest.mark.parametrize("chain_id", [None, 1, 31337, 0])
    def test_unknown_chain_keeps_the_single_legacy_default(self, chain_id: int | None) -> None:
        assert default_currencies_for_chain(chain_id) == (default_currency_for_chain(chain_id),)
        assert default_currencies_for_chain(chain_id) == (PATH_USD,)

    def test_default_currency_for_chain_is_unchanged(self) -> None:
        assert default_currency_for_chain(CHAIN_ID) == USDC
        assert default_currency_for_chain(TESTNET_CHAIN_ID) == PATH_USD
        assert default_currency_for_chain(None) == PATH_USD
        assert default_currency_for_chain(31337) == PATH_USD
        assert dict(DEFAULT_CURRENCIES) == {4217: USDC, 42431: PATH_USD}

    def test_fee_tokens_are_unchanged_and_exclude_ousd(self) -> None:
        assert dict(FEE_TOKENS) == {
            4217: (
                "0x20c0000000000000000000000000000000000000",
                "0x20C000000000000000000000b9537d11c60E8b50",
            ),
            42431: ("0x20c0000000000000000000000000000000000000",),
        }
        assert fee_tokens_for_chain(CHAIN_ID) == (PATH_USD, USDC)
        assert fee_tokens_for_chain(TESTNET_CHAIN_ID) == (PATH_USD,)
        assert fee_tokens_for_chain(31337) == (PATH_USD,)
        for tokens in FEE_TOKENS.values():
            assert OUSD.lower() not in {token.lower() for token in tokens}
            assert MACH.lower() not in {token.lower() for token in tokens}

    def test_fee_payer_policies_are_unchanged(self) -> None:
        assert DEFAULT_POLICY == Policy(
            max_gas=2_000_000,
            max_fee_per_gas=100_000_000_000,
            max_priority_fee_per_gas=10_000_000_000,
            max_total_fee=50_000_000_000_000_000,
            max_validity_window_seconds=900,
        )
        assert POLICY_BY_CHAIN_ID == {
            4217: DEFAULT_POLICY,
            42431: replace(DEFAULT_POLICY, max_priority_fee_per_gas=50_000_000_000),
        }

    def test_default_accepted_currencies_are_read_only(self) -> None:
        assert isinstance(DEFAULT_ACCEPTED_CURRENCIES, MappingProxyType)
        assert dict(DEFAULT_ACCEPTED_CURRENCIES) == {
            4217: (OUSD, USDC),
            42431: (OUSD, PATH_USD),
        }
        with pytest.raises(TypeError):
            cast(Any, DEFAULT_ACCEPTED_CURRENCIES)[1] = (OUSD,)


# ──────────────────────────────────────────────────────────────────
# tempo(currencies=...) configuration
# ──────────────────────────────────────────────────────────────────


class TestFactory:
    def test_mainnet_defaults(self) -> None:
        method, _ = server_method()
        assert method.chain_id == CHAIN_ID
        assert method.currencies == (OUSD, USDC)
        # The singular default (and client behavior) is unchanged.
        assert method.currency == USDC
        assert method._currency_explicit is False

    def test_moderato_defaults(self) -> None:
        method, _ = server_method(chain_id=TESTNET_CHAIN_ID)
        assert method.currencies == (OUSD, PATH_USD)
        assert method.currency == PATH_USD
        assert method._currency_explicit is False

    def test_rpc_url_does_not_infer_the_chain(self) -> None:
        # The factory never queries the RPC; an unset chain_id means mainnet.
        method, _ = server_method(rpc_url="https://rpc.moderato.tempo.xyz")
        assert method.chain_id == CHAIN_ID
        assert method.currencies == (OUSD, USDC)

    def test_explicit_chain_id_beats_rpc_url(self) -> None:
        method, _ = server_method(chain_id=TESTNET_CHAIN_ID, rpc_url="https://rpc.tempo.xyz")
        assert method.chain_id == TESTNET_CHAIN_ID
        assert method.currencies == (OUSD, PATH_USD)

    @pytest.mark.parametrize("chain_id", [None, 31337])
    def test_unknown_chain_keeps_single_legacy_default(self, chain_id: int | None) -> None:
        method, _ = server_method(chain_id=chain_id, rpc_url="http://localhost:8545")
        assert method.currencies == (PATH_USD,)
        assert method.currency == PATH_USD

    def test_explicit_list_replaces_defaults_and_preserves_order(self) -> None:
        method, _ = server_method(currencies=[PATH_USD, USDC])
        assert method.currencies == (PATH_USD, USDC)
        assert method.currency == PATH_USD
        assert method._currency_explicit is True

    def test_explicit_list_ignores_chain_defaults(self) -> None:
        method, _ = server_method(chain_id=TESTNET_CHAIN_ID, currencies=(USDC, OUSD))
        assert method.currencies == (USDC, OUSD)

    def test_single_element_list(self) -> None:
        method, _ = server_method(currencies=[USDC])
        assert method.currencies == (USDC,)
        assert method.currency == USDC

    def test_any_iterable_sequence_is_accepted(self) -> None:
        method, _ = server_method(currencies=cast(Any, iter([OUSD, USDC])))
        assert method.currencies == (OUSD, USDC)

    def test_legacy_currency_restricts_to_one(self) -> None:
        method, _ = server_method(currency=USDC)
        assert method.currencies == (USDC,)
        assert method.currency == USDC
        assert method._currency_explicit is True

    def test_legacy_currency_is_not_validated(self) -> None:
        # Preserves existing behavior for non-address currency identifiers.
        method, _ = server_method(currency="0xUsdc")
        assert method.currencies == ("0xUsdc",)

    def test_currency_and_currencies_are_mutually_exclusive(self) -> None:
        with pytest.raises(ValueError, match="not both"):
            server_method(currency=USDC, currencies=[OUSD])
        with pytest.raises(ValueError, match="not both"):
            server_method(currency=USDC, currencies=[])

    @pytest.mark.parametrize("empty", [[], ()])
    def test_empty_list_is_rejected(self, empty: Any) -> None:
        with pytest.raises(ValueError, match="at least one currency"):
            server_method(currencies=empty)

    def test_mixed_case_duplicates_are_removed_preserving_first(self) -> None:
        method, _ = server_method(
            currencies=[OUSD, swap_case(OUSD), USDC, OUSD.lower(), USDC.lower(), PATH_USD]
        )
        assert method.currencies == (OUSD, USDC, PATH_USD)

    @pytest.mark.parametrize(
        "invalid",
        [
            "0x123",
            "not-an-address",
            "20c0000000000000000000006a37DA5C996874BE",
            OUSD + "00",
            "0x20c0000000000000000000006a37DA5C996874BG",
            "",
            None,
            4217,
        ],
    )
    def test_invalid_address_is_rejected(self, invalid: Any) -> None:
        with pytest.raises(ValueError, match="Invalid Tempo currency address"):
            server_method(currencies=[OUSD, invalid])

    def test_bare_string_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="not a string"):
            server_method(currencies=cast(Any, OUSD))

    def test_direct_dataclass_construction_offers_only_currency(self) -> None:
        method = TempoMethod(currency=USDC, recipient=RECIPIENT)
        assert method.currencies == ()


# ──────────────────────────────────────────────────────────────────
# Issued challenges
# ──────────────────────────────────────────────────────────────────


class TestChallenges:
    @pytest.mark.asyncio
    async def test_mainnet_offers_ousd_then_usdc(self) -> None:
        method, _ = server_method()
        result = await create_server(method).charge(None, "0.50")

        assert isinstance(result, ComposedChallenges)
        assert currencies_of(result) == [OUSD, USDC]
        for challenge in result.challenges:
            assert challenge.method == "tempo"
            assert challenge.intent == "charge"
            assert challenge.realm == REALM
            assert challenge.request == {
                "amount": "500000",
                "currency": challenge.request["currency"],
                "recipient": RECIPIENT,
                "methodDetails": {"chainId": CHAIN_ID},
            }
        assert len({challenge.id for challenge in result.challenges}) == 2

    @pytest.mark.asyncio
    async def test_moderato_offers_ousd_then_path_usd(self) -> None:
        method, _ = server_method(chain_id=TESTNET_CHAIN_ID)
        result = await create_server(method).charge(None, "1")

        assert currencies_of(result) == [OUSD, PATH_USD]
        assert all(
            challenge.request["methodDetails"] == {"chainId": TESTNET_CHAIN_ID}
            for challenge in challenges_of(result)
        )

    @pytest.mark.asyncio
    async def test_unknown_chain_issues_one_plain_challenge(self) -> None:
        method, _ = server_method(chain_id=31337, rpc_url="http://localhost:8545")
        result = await create_server(method).charge(None, "1")

        assert isinstance(result, Challenge)
        assert result.request["currency"] == PATH_USD

    @pytest.mark.asyncio
    async def test_legacy_currency_issues_one_plain_challenge(self) -> None:
        method, _ = server_method(currency=USDC)
        result = await create_server(method).charge(None, "1")

        assert isinstance(result, Challenge)
        assert result.request["currency"] == USDC

    @pytest.mark.asyncio
    async def test_single_element_list_issues_one_plain_challenge(self) -> None:
        method, _ = server_method(currencies=[OUSD])
        result = await create_server(method).charge(None, "1")

        assert isinstance(result, Challenge)
        assert result.request["currency"] == OUSD

    @pytest.mark.asyncio
    async def test_explicit_order_is_the_offer_order(self) -> None:
        method, _ = server_method(currencies=[PATH_USD, OUSD, USDC])
        result = await create_server(method).charge(None, "1")

        assert currencies_of(result) == [PATH_USD, OUSD, USDC]

    @pytest.mark.asyncio
    async def test_per_request_currency_override_issues_one_challenge(self) -> None:
        method, _ = server_method()
        result = await create_server(method).charge(None, "1", currency=PATH_USD)

        assert isinstance(result, Challenge)
        assert result.request["currency"] == PATH_USD

    @pytest.mark.asyncio
    async def test_methods_list_expands_currencies_before_other_methods(self) -> None:
        method, _ = server_method()
        other = OtherMethod()
        server = Mpp.create(methods=[method, other], realm=REALM, secret_key=SECRET)
        result = await server.charge(None, "1")

        challenges = challenges_of(result)
        assert [(c.method, c.request["currency"]) for c in challenges] == [
            ("tempo", OUSD),
            ("tempo", USDC),
            ("other", "usd"),
        ]

    @pytest.mark.asyncio
    async def test_single_method_list_returns_all_currency_challenges(self) -> None:
        method, _ = server_method()
        server = Mpp.create(methods=[method], realm=REALM, secret_key=SECRET)

        assert currencies_of(await server.charge(None, "1")) == [OUSD, USDC]

    @pytest.mark.asyncio
    async def test_explicit_compose_expands_unless_offer_sets_currency(self) -> None:
        method, _ = server_method()
        server = create_server(method)

        expanded = await server.compose((method, {"amount": "1"})).verify(None)
        pinned = await server.compose((method, {"amount": "1", "currency": USDC})).verify(None)

        assert currencies_of(expanded) == [OUSD, USDC]
        assert currencies_of(pinned) == [USDC]

    @pytest.mark.asyncio
    async def test_can_offer_filters_each_currency_offer(self) -> None:
        method, _ = server_method(can_offer=lambda request: request["currency"] != OUSD)
        result = await create_server(method).charge(None, "1")

        assert currencies_of(result) == [USDC]

    @pytest.mark.asyncio
    async def test_pay_decorator_emits_one_header_per_currency(self) -> None:
        method, _ = server_method()
        server = create_server(method)

        @server.pay(amount="0.25")
        async def endpoint(_request: MockRequest, credential: Credential, receipt: Receipt) -> Any:
            return {"reference": receipt.reference, "currency": credential.challenge.id}

        response = await endpoint(MockRequest(path="/paid"))
        challenges = response_challenges(response)

        assert [c.request["currency"] for c in challenges] == [OUSD, USDC]
        assert all(c.request["amount"] == "250000" for c in challenges)

    @pytest.mark.asyncio
    async def test_pay_decorator_currency_override_emits_one_header(self) -> None:
        method, _ = server_method()
        server = create_server(method)

        @server.pay(amount="0.25", currency=USDC)
        async def endpoint(_request: MockRequest, credential: Credential, receipt: Receipt) -> Any:
            return receipt.reference

        challenges = response_challenges(await endpoint(MockRequest(path="/paid")))
        assert [c.request["currency"] for c in challenges] == [USDC]

    @pytest.mark.asyncio
    async def test_challenge_created_event_fires_per_offer(self) -> None:
        method, _ = server_method()
        server = create_server(method)
        created: list[Any] = []
        server.on_challenge_created(created.append)

        await server.charge(None, "1")

        assert [event["challenge"].request["currency"] for event in created] == [OUSD, USDC]


# ──────────────────────────────────────────────────────────────────
# Credential verification
# ──────────────────────────────────────────────────────────────────


class TestVerification:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("index,currency", [(0, OUSD), (1, USDC)])
    async def test_credential_for_any_offered_currency_verifies(
        self, index: int, currency: str
    ) -> None:
        method, intent = server_method()
        server = create_server(method)
        unpaid = challenges_of(await server.charge(None, "0.50"))

        paid = await server.charge(pay_with(unpaid[index]), "0.50")

        assert not isinstance(paid, Challenge | ComposedChallenges)
        credential, receipt = paid
        assert receipt.reference == f"paid-{currency}"
        assert credential.challenge.id == unpaid[index].id
        assert [request["currency"] for request in intent.requests] == [currency]

    @pytest.mark.asyncio
    async def test_moderato_path_usd_credential_verifies(self) -> None:
        method, intent = server_method(chain_id=TESTNET_CHAIN_ID)
        server = create_server(method)
        unpaid = challenges_of(await server.charge(None, "1"))

        paid = await server.charge(pay_with(unpaid[1]), "1")

        assert not isinstance(paid, Challenge | ComposedChallenges)
        assert intent.requests[0]["currency"] == PATH_USD

    @pytest.mark.asyncio
    async def test_credential_for_non_offered_currency_is_rejected(self) -> None:
        method, intent = server_method()
        server = create_server(method)
        # HMAC-valid for this server, but for a currency the route does not offer.
        forged = make_bound_credential(
            {},
            {
                "amount": "500000",
                "currency": PATH_USD,
                "recipient": RECIPIENT,
                "methodDetails": {"chainId": CHAIN_ID},
            },
            secret_key=SECRET,
            realm=REALM,
        )

        result = await server.charge(forged.to_authorization(), "0.50")

        assert isinstance(result, ComposedChallenges | Challenge)
        assert intent.requests == []

    @pytest.mark.asyncio
    async def test_credential_for_override_currency_is_rejected_on_default_route(self) -> None:
        method, intent = server_method()
        server = create_server(method)
        override = await server.charge(None, "0.50", currency=PATH_USD)
        assert isinstance(override, Challenge)

        result = await server.charge(pay_with(override), "0.50")

        # Existing compose routing re-challenges with the first offer only.
        assert isinstance(result, ComposedChallenges)
        assert currencies_of(result) == [OUSD]
        assert intent.requests == []

    @pytest.mark.asyncio
    async def test_default_credential_is_rejected_on_override_route(self) -> None:
        method, intent = server_method()
        server = create_server(method)
        unpaid = challenges_of(await server.charge(None, "0.50"))

        result = await server.charge(pay_with(unpaid[0]), "0.50", currency=USDC)

        assert isinstance(result, Challenge)
        assert result.request["currency"] == USDC
        assert intent.requests == []

    @pytest.mark.asyncio
    async def test_per_request_override_credential_verifies(self) -> None:
        method, intent = server_method()
        server = create_server(method)
        override = await server.charge(None, "0.50", currency=PATH_USD)
        assert isinstance(override, Challenge)

        paid = await server.charge(pay_with(override), "0.50", currency=PATH_USD)

        assert not isinstance(paid, Challenge | ComposedChallenges)
        assert intent.requests[0]["currency"] == PATH_USD

    @pytest.mark.asyncio
    async def test_credential_is_rejected_after_currency_removed_from_config(self) -> None:
        method, _ = server_method()
        unpaid = challenges_of(await create_server(method).charge(None, "0.50"))
        restricted, intent = server_method(currencies=[OUSD])

        result = await create_server(restricted).charge(pay_with(unpaid[1]), "0.50")

        assert isinstance(result, Challenge)
        assert result.request["currency"] == OUSD
        assert intent.requests == []

    @pytest.mark.asyncio
    async def test_pay_decorator_accepts_the_second_offer(self) -> None:
        method, intent = server_method()
        server = create_server(method)

        @server.pay(amount="0.25")
        async def endpoint(_request: MockRequest, credential: Credential, receipt: Receipt) -> Any:
            return receipt.reference

        challenges = response_challenges(await endpoint(MockRequest(path="/paid")))
        result = await endpoint(
            MockRequest(authorization=pay_with(challenges[1]), path="/paid"),
        )

        assert result == f"paid-{USDC}"
        assert [request["currency"] for request in intent.requests] == [USDC]


# ──────────────────────────────────────────────────────────────────
# End to end with real client signing and ChargeIntent validation
# ──────────────────────────────────────────────────────────────────


async def _fake_rpc_call(
    rpc_url: str,
    method_name: str,
    params: list[object],
    *,
    client: object | None = None,
) -> str:
    del rpc_url, params, client
    return {"eth_chainId": hex(CHAIN_ID), "eth_getTransactionCount": "0x0", "eth_gasPrice": "0x1"}[
        method_name
    ]


async def _sign(client_method: TempoMethod, challenge: Challenge) -> Credential:
    with (
        patch("mpp.methods.tempo.client._rpc_call", side_effect=_fake_rpc_call),
        patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
    ):
        return await client_method.create_credential(challenge)


class TestEndToEnd:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("index,currency", [(0, OUSD), (1, USDC)])
    async def test_signed_transfer_validates_against_its_offer(
        self, index: int, currency: str
    ) -> None:
        server = create_server(tempo(intents={"charge": ChargeIntent()}, recipient=RECIPIENT))
        offers = challenges_of(await server.charge(None, "0.50"))
        client = tempo(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY),
            intents={"charge": ChargeIntent()},
        )

        credential = await _sign(client, offers[index])
        validation = await server.validate_credential(credential)

        assert validation.request["currency"] == currency
        assert validation.details["mode"] == "pull"

    @pytest.mark.asyncio
    async def test_signed_transfer_is_rejected_against_another_offer(self) -> None:
        server = create_server(tempo(intents={"charge": ChargeIntent()}, recipient=RECIPIENT))
        offers = challenges_of(await server.charge(None, "0.50"))
        client = tempo(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY),
            intents={"charge": ChargeIntent()},
        )
        usdc_credential = await _sign(client, offers[1])
        ousd_credential = await _sign(client, offers[0])
        # USDC.e transfer presented under the OUSD challenge.
        mismatched = Credential(
            challenge=ousd_credential.challenge,
            payload=usdc_credential.payload,
            source=usdc_credential.source,
        )

        with pytest.raises(VerificationError):
            await server.validate_credential(mismatched)


# ──────────────────────────────────────────────────────────────────
# Client selection among multiple Tempo offers
# ──────────────────────────────────────────────────────────────────


class TestClientSelection:
    @pytest.fixture
    async def offers(self) -> tuple[Challenge, ...]:
        method, _ = server_method()
        return challenges_of(await create_server(method).charge(None, "1"))

    def test_default_client_picks_the_first_offer(self, offers: tuple[Challenge, ...]) -> None:
        client = tempo(intents={"charge": ChargeIntent()})
        # No balance check: a default client takes the first matching offer (OUSD).
        assert PaymentRuntime([client]).match_challenge(offers) == (offers[0], client)

    def test_client_currency_selects_the_matching_offer(
        self, offers: tuple[Challenge, ...]
    ) -> None:
        client = tempo(intents={"charge": ChargeIntent()}, currency=USDC)
        assert PaymentRuntime([client]).match_challenge(offers) == (offers[1], client)

    def test_client_currencies_accept_any_listed_offer(self, offers: tuple[Challenge, ...]) -> None:
        client = tempo(intents={"charge": ChargeIntent()}, currencies=[PATH_USD, swap_case(USDC)])
        assert PaymentRuntime([client]).match_challenge(offers) == (offers[1], client)

    def test_client_without_an_offered_currency_fails(self, offers: tuple[Challenge, ...]) -> None:
        client = tempo(intents={"charge": ChargeIntent()}, currencies=[PATH_USD, OTHER_TOKEN])
        with pytest.raises(ValueError, match="No compatible payment method"):
            PaymentRuntime([client]).match_challenge(offers)


# Pre-change single defaults, pinned literally (main: DEFAULT_CURRENCIES).
PRE_CHANGE_DEFAULTS = {
    4217: "0x20C000000000000000000000b9537d11c60E8b50",
    42431: "0x20c0000000000000000000000000000000000000",
}


class TestClientDefaultsUnchanged:
    @pytest.mark.parametrize("chain_id", [CHAIN_ID, TESTNET_CHAIN_ID])
    def test_client_default_currency_matches_main(self, chain_id: int) -> None:
        client = tempo(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY),
            chain_id=chain_id,
            intents={"charge": ChargeIntent()},
        )
        assert client.currency == PRE_CHANGE_DEFAULTS[chain_id]
        assert client._currency_explicit is False

    def test_client_default_currency_without_chain_id_matches_main(self) -> None:
        client = tempo(account=TempoAccount.from_key(TEST_PRIVATE_KEY), intents={})
        assert client.currency == PRE_CHANGE_DEFAULTS[CHAIN_ID]


# ──────────────────────────────────────────────────────────────────
# Local fee sponsorship pays gas in a fee token, not the charge currency
# ──────────────────────────────────────────────────────────────────

FEE_PAYER_KEY = "0x" + "ab" * 32


class FakeRpc:
    """Tempo RPC for a sponsored broadcast: simulation and a matching receipt."""

    def __init__(self) -> None:
        self.methods: list[str] = []
        self.broadcast: list[Any] | None = None

    async def post(self, url: str, json: dict[str, Any]) -> httpx.Response:
        self.methods.append(json["method"])
        if json["method"] == "tempo_simulateV1":
            result: Any = {"blocks": [{"calls": [{"status": "0x1"}]}]}
        elif json["method"] == "eth_sendRawTransactionSync":
            raw = json["params"][0]
            assert raw.startswith("0x76")
            self.broadcast = rlp.decode(bytes.fromhex(raw[2:])[1:])
            token, _, data = self.broadcast[4][0]
            recipient_topic = "0x" + data[4:36].hex()
            result = {
                "transactionHash": _raw_transaction_hash(raw),
                "status": "0x1",
                "logs": [
                    {
                        "address": "0x" + token.hex(),
                        "topics": [
                            TRANSFER_WITH_MEMO_TOPIC,
                            "0x" + "0" * 24 + "ab" * 20,
                            recipient_topic,
                            "0x" + data[68:100].hex(),
                        ],
                        "data": "0x" + data[36:68].hex(),
                    }
                ],
            }
        else:
            raise AssertionError(f"unexpected RPC method {json['method']}")
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": result},
            request=httpx.Request("POST", url),
        )

    @property
    def fee_token(self) -> str:
        assert self.broadcast is not None
        return "0x" + self.broadcast[10].hex()


def balances(funded: Mapping[str, int]) -> tuple[AsyncMock, list[str]]:
    """Patchable ``_tip20_balance`` returning ``funded`` balances by token."""
    queried: list[str] = []

    async def balance(rpc_url: str, token: str, account: str, *, client: Any = None) -> int:
        del rpc_url, client
        assert account == TempoAccount.from_key(FEE_PAYER_KEY).address
        queried.append(token)
        amount = funded.get(token.lower(), 0)
        if amount < 0:
            raise RuntimeError("rpc failure")
        return amount

    return AsyncMock(side_effect=balance), queried


async def _fake_client_rpc(chain_id: int) -> Any:
    async def call(rpc_url: str, method_name: str, params: list[object], *, client: Any = None):
        del rpc_url, params, client
        return {
            "eth_chainId": hex(chain_id),
            "eth_getTransactionCount": "0x0",
            "eth_gasPrice": "0x1",
        }[method_name]

    return call


def sponsored_server(rpc: FakeRpc, chain_id: int = CHAIN_ID, **kwargs: Any) -> Mpp:
    method = tempo(
        intents={"charge": ChargeIntent(http_client=cast(Any, rpc))},
        recipient=RECIPIENT,
        chain_id=chain_id,
        fee_payer=TempoAccount.from_key(FEE_PAYER_KEY),
        **kwargs,
    )
    return create_server(method)


def charge_request(chain_id: int | None = CHAIN_ID) -> ChargeRequest:
    details: dict[str, Any] = {"feePayer": True}
    if chain_id is not None:
        details["chainId"] = chain_id
    return ChargeRequest.model_validate(
        {"amount": "1", "currency": OUSD, "recipient": RECIPIENT, "methodDetails": details}
    )


def sponsor_intent(chain_id: int | None = CHAIN_ID, **kwargs: Any) -> ChargeIntent:
    intent = ChargeIntent()
    rpc = {} if chain_id in (CHAIN_ID, TESTNET_CHAIN_ID) else {"rpc_url": "http://x"}
    tempo(
        intents={"charge": intent},
        chain_id=chain_id,
        fee_payer=TempoAccount.from_key(FEE_PAYER_KEY),
        **rpc,
        **kwargs,
    )
    return intent


class TestSponsoredFeeToken:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "chain_id,funded,expected_fee_token",
        [
            (CHAIN_ID, {USDC.lower(): 5}, USDC),
            (CHAIN_ID, {PATH_USD.lower(): 5, USDC.lower(): 5}, PATH_USD),
            (TESTNET_CHAIN_ID, {PATH_USD.lower(): 5}, PATH_USD),
        ],
    )
    async def test_sponsored_ousd_charge_with_defaults_succeeds(
        self, chain_id: int, funded: dict[str, int], expected_fee_token: str
    ) -> None:
        rpc = FakeRpc()
        server = sponsored_server(rpc, chain_id)
        offers = challenges_of(await server.charge(None, "0.50", fee_payer=True))
        assert [c.request["currency"] for c in offers] == list(
            default_currencies_for_chain(chain_id)
        )
        assert all(c.request["methodDetails"]["feePayer"] is True for c in offers)
        client = tempo(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY),
            chain_id=chain_id,
            intents={"charge": ChargeIntent()},
        )
        with (
            patch(
                "mpp.methods.tempo.client._rpc_call",
                side_effect=await _fake_client_rpc(chain_id),
            ),
            patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
        ):
            credential = await client.create_credential(offers[0])
        balance, _ = balances(funded)

        with patch("mpp.methods.tempo.intents._tip20_balance", new=balance):
            paid = await server.charge(credential.to_authorization(), "0.50", fee_payer=True)

        assert not isinstance(paid, Challenge | ComposedChallenges)
        assert paid[1].status == "success"
        assert rpc.methods == ["tempo_simulateV1", "eth_sendRawTransactionSync"]
        assert rpc.broadcast is not None
        assert "0x" + rpc.broadcast[4][0][0].hex() == OUSD.lower()
        assert rpc.fee_token == expected_fee_token.lower()
        assert rpc.fee_token != OUSD.lower()

    @pytest.mark.asyncio
    async def test_sponsored_defaults_offer_both_currencies(self) -> None:
        rpc = FakeRpc()
        for chain_id in (CHAIN_ID, TESTNET_CHAIN_ID):
            result = await sponsored_server(rpc, chain_id).charge(None, "1", fee_payer=True)
            assert isinstance(result, ComposedChallenges)
            assert currencies_of(result) == list(default_currencies_for_chain(chain_id))

    @pytest.mark.asyncio
    async def test_first_funded_allowed_token_wins(self) -> None:
        balance, queried = balances({USDC.lower(): 1})
        with patch("mpp.methods.tempo.intents._tip20_balance", new=balance):
            fee_token = await sponsor_intent()._resolve_fee_token(None, charge_request())
        assert fee_token == USDC
        assert queried == [PATH_USD, USDC]

    @pytest.mark.asyncio
    async def test_balance_lookup_stops_at_first_funded_token(self) -> None:
        balance, queried = balances({PATH_USD.lower(): 1, USDC.lower(): 1})
        with patch("mpp.methods.tempo.intents._tip20_balance", new=balance):
            fee_token = await sponsor_intent()._resolve_fee_token(None, charge_request())
        assert fee_token == PATH_USD
        assert queried == [PATH_USD]

    @pytest.mark.asyncio
    async def test_no_funded_token_falls_back_to_first_allowed(self) -> None:
        balance, queried = balances({PATH_USD.lower(): -1})
        with patch("mpp.methods.tempo.intents._tip20_balance", new=balance):
            fee_token = await sponsor_intent()._resolve_fee_token(None, charge_request())
        assert fee_token == PATH_USD
        assert queried == [PATH_USD, USDC]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "chain_id,expected", [(TESTNET_CHAIN_ID, [PATH_USD]), (31337, [PATH_USD])]
    )
    async def test_default_allowed_tokens_follow_fee_tokens_for_chain(
        self, chain_id: int, expected: list[str]
    ) -> None:
        balance, queried = balances({})
        with patch("mpp.methods.tempo.intents._tip20_balance", new=balance):
            fee_token = await sponsor_intent(chain_id)._resolve_fee_token(
                None, charge_request(chain_id)
            )
        assert fee_token == PATH_USD
        assert queried == expected

    @pytest.mark.asyncio
    async def test_request_chain_id_selects_allowed_tokens(self) -> None:
        balance, queried = balances({})
        with patch("mpp.methods.tempo.intents._tip20_balance", new=balance):
            await sponsor_intent(CHAIN_ID)._resolve_fee_token(None, charge_request(42431))
        assert queried == [PATH_USD]

    @pytest.mark.asyncio
    async def test_configured_fee_token_wins_without_balance_lookup(self) -> None:
        balance, queried = balances({PATH_USD.lower(): 1})
        intent = sponsor_intent(fee_token=USDC)
        with patch("mpp.methods.tempo.intents._tip20_balance", new=balance):
            fee_token = await intent._resolve_fee_token(None, charge_request())
        assert fee_token == USDC
        assert queried == []

    @pytest.mark.asyncio
    async def test_explicit_allowlist_is_respected(self) -> None:
        balance, queried = balances({PATH_USD.lower(): 1})
        intent = sponsor_intent(allowed_fee_tokens=[USDC])
        with patch("mpp.methods.tempo.intents._tip20_balance", new=balance):
            fee_token = await intent._resolve_fee_token(None, charge_request())
        assert fee_token == USDC
        assert queried == [USDC]

    @pytest.mark.asyncio
    async def test_explicit_allowlist_order_is_the_preference_order(self) -> None:
        balance, queried = balances({PATH_USD.lower(): 1, USDC.lower(): 1})
        intent = sponsor_intent(allowed_fee_tokens=[USDC, PATH_USD])
        with patch("mpp.methods.tempo.intents._tip20_balance", new=balance):
            fee_token = await intent._resolve_fee_token(None, charge_request())
        assert fee_token == USDC
        assert queried == [USDC]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"fee_token": OUSD},
            {"fee_token": USDC, "allowed_fee_tokens": [PATH_USD]},
        ],
    )
    async def test_disallowed_fee_token_is_rejected(self, kwargs: dict[str, Any]) -> None:
        intent = sponsor_intent(**kwargs)
        with pytest.raises(VerificationError, match="feeToken is not allowed"):
            await intent._resolve_fee_token(None, charge_request())

    @pytest.mark.asyncio
    async def test_configured_fee_token_matches_case_insensitively(self) -> None:
        intent = sponsor_intent(fee_token=swap_case(USDC))
        assert await intent._resolve_fee_token(None, charge_request()) == swap_case(USDC)

    @pytest.mark.asyncio
    async def test_resolution_requires_a_local_fee_payer(self) -> None:
        with pytest.raises(VerificationError, match="No fee payer"):
            await ChargeIntent()._resolve_fee_token(None, charge_request())

    def test_fee_token_requires_local_fee_payer(self) -> None:
        with pytest.raises(ValueError, match="local fee_payer"):
            tempo(intents={}, fee_token=USDC)

    @pytest.mark.parametrize(
        "kwargs,match",
        [
            ({"fee_token": "0x123"}, "Invalid Tempo fee token"),
            ({"allowed_fee_tokens": []}, "at least one token"),
            ({"allowed_fee_tokens": ["nope"]}, "Invalid Tempo fee token"),
            ({"allowed_fee_tokens": PATH_USD}, "sequence of addresses"),
        ],
    )
    def test_fee_token_configuration_is_validated(self, kwargs: dict[str, Any], match: str) -> None:
        with pytest.raises(ValueError, match=match):
            tempo(intents={}, fee_payer=TempoAccount.from_key(FEE_PAYER_KEY), **kwargs)

    def test_fee_token_configuration_is_stored(self) -> None:
        method = tempo(
            intents={},
            fee_payer=TempoAccount.from_key(FEE_PAYER_KEY),
            fee_token=USDC,
            allowed_fee_tokens=(PATH_USD, USDC),
        )
        assert method.fee_token == USDC
        assert method.allowed_fee_tokens == (PATH_USD, USDC)
        assert tempo(intents={}).allowed_fee_tokens is None
