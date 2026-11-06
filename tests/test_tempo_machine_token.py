"""Machine-token (MACH) charge routes, as mppx's machine-token charges."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import rlp

from mpp import Challenge
from mpp.errors import VerificationError
from mpp.methods.tempo import CHAIN_ID, MACH, PATH_USD, TESTNET_CHAIN_ID, TempoAccount
from mpp.methods.tempo import _machine_token as machine_token
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo.client import _tempo_method
from mpp.methods.tempo.intents import TRANSFER_WITH_MEMO_TOPIC, ChargeIntent
from mpp.methods.tempo.schemas import ChargeInput, ChargeRequest, MethodDetails
from mpp.server.method import RequestContext

TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CURRENCY = "0x20c0000000000000000000000000000000000001"
RECIPIENT = "0x2222222222222222222222222222222222222222"
PAYER = "0x1111111111111111111111111111111111111111"
MEMO = "0x" + "ab" * 32
AMOUNT = 1_000_000
DEPLOYMENT = machine_token.DEPLOYMENTS[TESTNET_CHAIN_ID]


def _route() -> machine_token.Route:
    route = machine_token.get_route(
        chain_id=TESTNET_CHAIN_ID, currency=CURRENCY, amount=AMOUNT, recipient=RECIPIENT, memo=MEMO
    )
    assert route is not None
    return route


def _calls(route: machine_token.Route) -> list[tuple[str, int, str]]:
    # Normalized as decoded transactions are: lowercase targets, unprefixed calldata.
    return [(to.lower(), 0, data.removeprefix("0x")) for to, data in route.calls]


def _request(*, enabled: bool = True, chain_id: int = TESTNET_CHAIN_ID) -> ChargeRequest:
    return ChargeRequest(
        amount=str(AMOUNT),
        currency=CURRENCY,
        recipient=RECIPIENT,
        methodDetails=MethodDetails(chainId=chain_id, machineTokenEnabled=enabled or None),
    )


class TestRoute:
    def test_builds_the_exact_approve_and_swap_to_calls(self) -> None:
        route = _route()
        (approve_to, approve), (swap_to, swap) = route.calls
        assert approve_to == MACH
        assert approve == (
            "0x095ea7b3" + DEPLOYMENT.swap[2:].lower().rjust(64, "0") + format(AMOUNT, "064x")
        )
        assert swap_to == DEPLOYMENT.swap
        assert swap.startswith("0x34189fed")
        assert swap.endswith(MEMO[2:])
        assert route.settlement_sender == DEPLOYMENT.swap

    @pytest.mark.parametrize("memo", [MEMO, None])
    def test_matches_the_route_with_or_without_the_expected_memo(self, memo: str | None) -> None:
        route = _route()
        matched = machine_token.match_route(
            _calls(route),
            chain_id=TESTNET_CHAIN_ID,
            currency=CURRENCY,
            amount=AMOUNT,
            recipient=RECIPIENT,
            memo=memo,
        )
        assert matched == route

    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda c: [c[0]], id="missing-swap"),
            pytest.param(lambda c: [*c, c[1]], id="extra-call"),
            pytest.param(lambda c: [(c[0][0], 1, c[0][2]), c[1]], id="call-value"),
            pytest.param(lambda c: [(PATH_USD, 0, c[0][2]), c[1]], id="other-approve-token"),
            pytest.param(lambda c: [c[0], (c[1][0], 0, "00000000" + c[1][2][8:])], id="selector"),
            pytest.param(
                lambda c: [c[0], (c[1][0], 0, c[1][2].replace(RECIPIENT[2:], PAYER[2:]))],
                id="other-recipient",
            ),
        ],
    )
    def test_rejects_anything_but_the_exact_route(self, mutate: Any) -> None:
        assert (
            machine_token.match_route(
                mutate(_calls(_route())),
                chain_id=TESTNET_CHAIN_ID,
                currency=CURRENCY,
                amount=AMOUNT,
                recipient=RECIPIENT,
            )
            is None
        )

    def test_no_route_without_a_deployment_or_memo(self) -> None:
        common: dict[str, Any] = {"currency": CURRENCY, "amount": AMOUNT, "recipient": RECIPIENT}
        assert machine_token.get_route(chain_id=1, memo=MEMO, **common) is None
        assert machine_token.get_route(chain_id=TESTNET_CHAIN_ID, memo=None, **common) is None
        assert machine_token.get_route(chain_id=TESTNET_CHAIN_ID, memo="0x1234", **common) is None
        assert machine_token.is_supported(CHAIN_ID)
        assert not machine_token.is_supported(1)


class TestServer:
    def test_charge_input_advertises_machine_token_enabled(self) -> None:
        wire = ChargeInput.model_validate(
            {
                "amount": "1",
                "currency": CURRENCY,
                "recipient": RECIPIENT,
                "chain_id": TESTNET_CHAIN_ID,
                "machine_token_enabled": True,
            }
        ).model_dump()
        assert wire["methodDetails"] == {"chainId": TESTNET_CHAIN_ID, "machineTokenEnabled": True}
        plain = ChargeInput.model_validate(
            {
                "amount": "1",
                "currency": CURRENCY,
                "recipient": RECIPIENT,
                "machine_token_enabled": False,
            }
        ).model_dump()
        assert "methodDetails" not in plain

    def test_charge_input_rejects_unsupported_chains_and_mach_currency(self) -> None:
        with pytest.raises(ValueError, match="not supported on chainId 1"):
            ChargeInput.model_validate(
                {
                    "amount": "1",
                    "currency": CURRENCY,
                    "recipient": RECIPIENT,
                    "chain_id": 1,
                    "machine_token_enabled": True,
                }
            )
        with pytest.raises(ValueError, match="MACH cannot be advertised"):
            ChargeInput.model_validate(
                {
                    "amount": "1",
                    "currency": MACH,
                    "recipient": RECIPIENT,
                    "chain_id": CHAIN_ID,
                    "machine_token_enabled": True,
                }
            )

    def test_server_charge_enables_it_for_every_route(self) -> None:
        methods = tempo_server.charge(
            recipient=RECIPIENT, chain_id=TESTNET_CHAIN_ID, machine_token_enabled=True
        )
        resolve = methods[0].resolve_request
        assert resolve is not None
        resolved = resolve(RequestContext(request={"amount": "1"}))
        assert isinstance(resolved, dict)
        assert resolved["machine_token_enabled"] is True
        overridden = resolve(
            RequestContext(request={"amount": "1", "machine_token_enabled": False})
        )
        assert isinstance(overridden, dict)
        assert overridden["machine_token_enabled"] is False

    def test_pull_accepts_the_route_only_when_enabled(self) -> None:
        calls = _calls(_route())
        from mpp.methods.tempo.intents import _calls_funding_currency, _validate_normalized_calls

        legs = _validate_normalized_calls(calls, _request())
        assert [(leg.kind, leg.memo) for leg in legs] == [("memo", MEMO)]
        assert _calls_funding_currency(calls, _request()) == MACH.lower()
        with pytest.raises(VerificationError):
            _validate_normalized_calls(calls, _request(enabled=False))
        with pytest.raises(VerificationError):
            _validate_normalized_calls(calls, _request(chain_id=1))

    @staticmethod
    def _receipt(memo: str) -> dict[str, Any]:
        def word(address: str) -> str:
            return "0x" + address[2:].lower().rjust(64, "0")

        return {
            "status": "0x1",
            "from": PAYER,
            "logs": [
                {
                    "address": CURRENCY,
                    "topics": [
                        TRANSFER_WITH_MEMO_TOPIC,
                        word(DEPLOYMENT.swap),
                        word(RECIPIENT),
                        memo,
                    ],
                    "data": "0x" + format(AMOUNT, "064x"),
                }
            ],
        }

    def test_hash_accepts_the_swapper_settling_for_the_sender(self) -> None:
        realm = "api.example.com"
        memo = encode_attribution(challenge_id="challenge", server_id=realm)
        intent = ChargeIntent(rpc_url="https://rpc.test")
        source = f"did:pkh:eip155:{TESTNET_CHAIN_ID}:{PAYER}"

        def verify(request: ChargeRequest, receipt: dict[str, Any]) -> list[Any]:
            return intent._verify_receipt_transfers(
                receipt,
                request,
                challenge_id="challenge",
                realm=realm,
                source=source,
                source_address=PAYER,
            )

        legs = verify(_request(), self._receipt(memo))
        assert [leg.sender for leg in legs] == [PAYER]
        # Without the hint, or for another transaction sender, the swapper is a stranger.
        with pytest.raises(VerificationError):
            verify(_request(enabled=False), self._receipt(memo))
        with pytest.raises(VerificationError):
            verify(_request(), {**self._receipt(memo), "from": RECIPIENT})


class TestClient:
    @staticmethod
    def _challenge(enabled: bool = True) -> Challenge:
        details: dict[str, Any] = {"chainId": TESTNET_CHAIN_ID}
        if enabled:
            details["machineTokenEnabled"] = True
        return Challenge(
            id="machine-token",
            method="tempo",
            intent="charge",
            realm="api.example.com",
            request={
                "amount": str(AMOUNT),
                "currency": CURRENCY,
                "recipient": RECIPIENT,
                "methodDetails": details,
            },
        )

    async def _pay(
        self, challenge: Challenge, mach_balance: int, simulates: bool = True
    ) -> tuple[list[Any], bytes, str]:
        method = _tempo_method(
            account=TempoAccount.from_key(TEST_PRIVATE_KEY),
            chain_id=TESTNET_CHAIN_ID,
            rpc_url="https://rpc.test",
        )

        async def fake_rpc_call(
            _rpc_url: str, method_name: str, _params: list[object], *, client: object = None
        ) -> str:
            del client
            if method_name == "eth_estimateGas" and not simulates:
                raise RuntimeError("execution reverted")
            return {
                "eth_chainId": hex(TESTNET_CHAIN_ID),
                "eth_gasPrice": "0x1",
                "eth_estimateGas": hex(300_000),
            }[method_name]

        async def fake_balance(_rpc_url: str, token: str, _address: str, **_: Any) -> int:
            if token.lower() == MACH.lower():
                return mach_balance
            return AMOUNT * 10 if token.lower() == PATH_USD.lower() else 0

        with (
            patch("mpp.methods.tempo.client._rpc_call", side_effect=fake_rpc_call),
            patch("mpp.methods.tempo.client._tip20_balance", side_effect=fake_balance),
            patch("mpp.methods.tempo.client.estimate_gas", new=AsyncMock(return_value=100_000)),
        ):
            credential = await method.create_credential(challenge)

        decoded = rlp.decode(bytes.fromhex(credential.payload["signature"][2:])[1:])
        calls = [(bytes(c[0]), bytes(c[2])) for c in decoded[4]]
        return calls, bytes(decoded[10]), credential.payload["signature"]

    @pytest.mark.asyncio
    async def test_pays_through_the_swapper_when_holding_mach(self) -> None:
        challenge = self._challenge()
        calls, fee_token, signature = await self._pay(challenge, mach_balance=AMOUNT)
        assert [to for to, _ in calls] == [
            bytes.fromhex(MACH[2:]),
            bytes.fromhex(DEPLOYMENT.swap[2:]),
        ]
        assert calls[1][1][:4].hex() == machine_token.SWAP_TO_SELECTOR
        # MACH cannot pay fees: a funded supported stablecoin does.
        assert fee_token == bytes.fromhex(PATH_USD[2:])
        # The server accepts the signed route, bound to this challenge.
        intent = ChargeIntent(rpc_url="https://rpc.test")
        request = ChargeRequest.model_validate(challenge.request)
        legs = intent._validate_transaction_payload(signature, request, strict=True)
        assert legs is not None
        intent._assert_challenge_bound_memo(legs, challenge_id=challenge.id, realm=challenge.realm)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("enabled", "mach_balance", "simulates"),
        [
            pytest.param(True, AMOUNT - 1, True, id="short-of-mach"),
            pytest.param(True, AMOUNT, False, id="route-reverts"),
            pytest.param(False, AMOUNT, True, id="off"),
        ],
    )
    async def test_pays_directly_otherwise(
        self, enabled: bool, mach_balance: int, simulates: bool
    ) -> None:
        calls, _, _ = await self._pay(
            self._challenge(enabled), mach_balance=mach_balance, simulates=simulates
        )
        assert [to for to, _ in calls] == [bytes.fromhex(CURRENCY[2:])]
