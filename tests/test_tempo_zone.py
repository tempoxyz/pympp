"""Zone payments for the Tempo charge method (mppx tempo zone tests)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

import httpx
import pytest
from eth_abi.abi import encode

from mpp import Challenge, Credential
from mpp.errors import (
    CredentialReplayedError,
    PaymentError,
    PaymentOutcomeUnknownError,
    VerificationError,
    ZoneSettlementPendingError,
)
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import _zone as zone_lib
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo.client import Zone, _tempo_method
from mpp.methods.tempo.intents import ChargeIntent
from mpp.server import Mpp
from mpp.store import MemoryStore
from tests import challenge as challenge_of
from tests import http_request

REALM = "api.example.com"
SECRET = "test-secret-key-test-secret-key-32"
MERCHANT = "0x2222222222222222222222222222222222222222"
OTHER = "0x3333333333333333333333333333333333333333"
SEQUENCER = "0x4444444444444444444444444444444444444444"
CURRENCY = "0x20c0000000000000000000000000000000000001"
OTHER_CURRENCY = "0x20c0000000000000000000000000000000000002"
MODERATO = 42_431
ZONE_ID = 3
PORTAL = zone_lib.portal_address(ZONE_ID)
SETTLEMENT_HASH = "0x" + "ab" * 32
TAG_A = "0x" + "a1" * 32
TAG_B = "0x" + "b2" * 32
PAYER = TempoAccount.from_key("0x" + "00" * 31 + "01")
WITHDRAWAL_TUPLE = "(address,bytes32,address,uint128,bytes32,uint64,uint64,bytes,bytes)"


def word(value: str) -> str:
    return "0x" + value.removeprefix("0x").lower().zfill(64)


def rpc_client(handler: Callable[[str, list[Any]], Any], calls: list[str] | None = None):
    """An httpx client answering JSON-RPC with `handler(method, params)`."""

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if calls is not None:
            calls.append(body["method"])
        result = handler(body["method"], body["params"])
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    return httpx.AsyncClient(transport=httpx.MockTransport(respond))


def process_withdrawals_data(withdrawals: list[tuple[Any, ...]]) -> str:
    data = encode([f"{WITHDRAWAL_TUPLE}[]", "bytes32"], [withdrawals, b"\x00" * 32])
    return "0x" + zone_lib.PROCESS_WITHDRAWALS_SELECTOR + data.hex()


def processed_log(
    *,
    sender_tag: str,
    to: str = MERCHANT,
    token: str = CURRENCY,
    amount: int = 1_000_000,
    callback_success: bool = True,
    address: str = PORTAL,
) -> dict[str, Any]:
    return {
        "address": address,
        "topics": [zone_lib.WITHDRAWAL_PROCESSED_TOPIC, word(to), sender_tag],
        "data": "0x"
        + encode(["address", "uint128", "bool"], [token, amount, callback_success]).hex(),
        "transactionHash": SETTLEMENT_HASH,
        "blockNumber": "0x10",
        "logIndex": "0x0",
    }


@dataclass
class Fixture:
    """A withdrawal a mocked Tempo settlement transaction pays."""

    sender_tag: str
    memo: str
    to: str = MERCHANT
    token: str = CURRENCY
    amount: int = 1_000_000
    gas_limit: int = 0
    callback_success: bool = True
    event_address: str = PORTAL
    in_calldata: bool = True


def tempo_rpc(withdrawals: Callable[[], list[Fixture]], status: str = "0x1"):
    """Tempo JSON-RPC answers for a settlement transaction paying `withdrawals`."""

    def handle(method: str, params: list[Any]) -> Any:
        if method == "eth_chainId":
            return hex(MODERATO)
        if method == "eth_getTransactionByHash":
            items = [
                (
                    w.token,
                    bytes.fromhex(w.sender_tag[2:]),
                    w.to,
                    w.amount,
                    bytes.fromhex(w.memo[2:]),
                )
                + (w.gas_limit, 1, b"", b"")
                for w in withdrawals()
                if w.in_calldata
            ]
            return {
                "hash": SETTLEMENT_HASH,
                "from": SEQUENCER,
                "type": "0x76",
                "calls": [{"to": PORTAL, "value": "0x0", "input": process_withdrawals_data(items)}],
            }
        if method == "eth_getTransactionReceipt":
            return {
                "transactionHash": SETTLEMENT_HASH,
                "from": SEQUENCER,
                "to": PORTAL,
                "status": status,
                "logs": [
                    processed_log(
                        sender_tag=w.sender_tag,
                        to=w.to,
                        token=w.token,
                        amount=w.amount,
                        callback_success=w.callback_success,
                        address=w.event_address,
                    )
                    for w in withdrawals()
                ],
            }
        raise AssertionError(f"unexpected {method}")

    return handle


def setup(
    withdrawals: Callable[[], list[Fixture]] = list,
    *,
    status: str = "0x1",
    zones: list[int] | None = None,
    rpc_methods: list[str] | None = None,
) -> Mpp:
    return Mpp(
        methods=tempo_server.charge(
            recipient=MERCHANT,
            currencies=[CURRENCY],
            chain_id=MODERATO,
            http_client=rpc_client(tempo_rpc(withdrawals, status), rpc_methods),
            store=MemoryStore(),
            zones=zones or [ZONE_ID],
        ),
        realm=REALM,
        secret_key=SECRET,
    )


def setup_any_zone(withdrawals: Callable[[], list[Fixture]] = list) -> Mpp:
    return Mpp(
        methods=tempo_server.charge(
            recipient=MERCHANT,
            currencies=[CURRENCY],
            chain_id=MODERATO,
            http_client=rpc_client(tempo_rpc(withdrawals)),
            store=MemoryStore(),
            zones=True,
        ),
        realm=REALM,
        secret_key=SECRET,
    )


async def issue(server: Mpp, **request: Any) -> tuple[Challenge, str]:
    issued = challenge_of(await server.charge(amount="1", **request)(http_request()))
    return issued, encode_attribution(challenge_id=issued.id, server_id=issued.realm)


def zone_credential(
    issued: Challenge, sender_tag: str, *, zone_id: Any = ZONE_ID, hash: str = SETTLEMENT_HASH
) -> Credential:
    payload = {"hash": hash, "senderTag": sender_tag, "type": "zone", "zoneId": zone_id}
    return Credential(challenge=issued.to_echo(), payload=payload)


class TestZoneHelpers:
    def test_id_from_chain_id(self) -> None:
        assert zone_lib.id_from_chain_id(421_700_003) == 3
        assert zone_lib.id_from_chain_id(1_424_310_003) == 3
        assert zone_lib.id_from_chain_id(1337 * 2**32 + 1) == 1
        with pytest.raises(ValueError, match="Cannot derive a Zone ID"):
            zone_lib.id_from_chain_id(42_431)

    def test_parent_chain_id_from_chain_id(self) -> None:
        assert zone_lib.parent_chain_id_from_chain_id(421_700_003) == 4_217
        assert zone_lib.parent_chain_id_from_chain_id(1_424_310_003) == 42_431
        assert zone_lib.parent_chain_id_from_chain_id(1337 * 2**32 + 1) == 1337
        assert zone_lib.parent_chain_id_from_chain_id(42_431) is None

    def test_portal_address(self) -> None:
        # Vectors from viem/tempo Addresses.zonePortal.
        assert zone_lib.portal_address(3) == "0x5ad0000000000000000000000000000000000003"
        assert zone_lib.portal_address(2**32 - 1) == "0x5ad00000000000000000000000000000ffffffff"
        assert zone_lib.portal_address(6) == "0x7069DeC4E64Fd07334A0933eDe836C17259c9B23"
        assert zone_lib.portal_address(1_424_310_009).endswith("0000000009")

    def test_sender_tag(self) -> None:
        # keccak256(encodePacked(['address', 'bytes32', 'uint64'], ...)) computed with viem.
        assert (
            zone_lib.sender_tag("0x1111111111111111111111111111111111111111", "0x" + "ab" * 32, 5)
            == "0x788fcff52bc1aca0be1c1ea444c37d65c3ace8da9b825356ab590beccac6a973"
        )

    @pytest.mark.parametrize("zone_id", [0, -1, 1.5, 2**32, True, "3"])
    def test_is_id_rejects(self, zone_id: Any) -> None:
        assert not zone_lib.is_id(zone_id)
        assert not zone_lib.is_accepted(True, zone_id)

    def test_is_accepted(self) -> None:
        assert zone_lib.is_accepted([3, 7], 7)
        assert not zone_lib.is_accepted([3, 7], 4)
        assert zone_lib.is_accepted(True, 4)
        assert not zone_lib.is_accepted(None, 3)


class TestServerZoneCredentials:
    @pytest.mark.asyncio
    async def test_advertises_accepted_zones(self) -> None:
        issued, _ = await issue(setup(zones=[3, 7]))
        assert issued.request["methodDetails"]["zones"] == [3, 7]

    @pytest.mark.asyncio
    async def test_accepts_a_settled_withdrawal_bound_to_the_challenge(self) -> None:
        fixture: list[Fixture] = []
        server = setup(lambda: fixture)
        issued, memo = await issue(server)
        fixture[:] = [Fixture(TAG_A, memo)]
        receipt = await server.broadcast_credential(zone_credential(issued, TAG_A))
        assert receipt.status == "success"
        assert receipt.reference == SETTLEMENT_HASH
        assert receipt.method == "tempo"

    @pytest.mark.asyncio
    async def test_validates_without_claiming(self) -> None:
        fixture: list[Fixture] = []
        server = setup(lambda: fixture)
        issued, memo = await issue(server)
        fixture[:] = [Fixture(TAG_A, memo)]
        validation = await server.validate_credential(zone_credential(issued, TAG_A))
        assert validation.details == {"mode": "push"}
        await server.broadcast_credential(zone_credential(issued, TAG_A))
        with pytest.raises(CredentialReplayedError, match="Zone withdrawal has already been used"):
            await server.validate_credential(zone_credential(issued, TAG_A))

    @pytest.mark.asyncio
    async def test_rejects_a_credential_without_a_settlement_hash(self) -> None:
        rpc_methods: list[str] = []
        server = setup(rpc_methods=rpc_methods)
        issued, _ = await issue(server)
        hashless = Credential(
            challenge=issued.to_echo(),
            payload={"senderTag": TAG_A, "type": "zone", "zoneId": ZONE_ID},
        )
        with pytest.raises(PaymentError):
            await server.broadcast_credential(hashless)
        assert "eth_getTransactionReceipt" not in rpc_methods

    @pytest.mark.asyncio
    async def test_rejects_a_replayed_withdrawal(self) -> None:
        fixture: list[Fixture] = []
        server = setup(lambda: fixture)
        issued, memo = await issue(server)
        fixture[:] = [Fixture(TAG_A, memo)]
        await server.broadcast_credential(zone_credential(issued, TAG_A))
        with pytest.raises(CredentialReplayedError, match="Zone withdrawal has already been used"):
            await server.broadcast_credential(zone_credential(issued, TAG_A))

    @pytest.mark.asyncio
    async def test_releases_the_claim_when_verification_fails(self) -> None:
        fixture: list[Fixture] = []
        server = setup(lambda: fixture)
        issued, memo = await issue(server)
        fixture[:] = [Fixture(TAG_A, memo, amount=1)]
        with pytest.raises(VerificationError, match="Zone withdrawal not found"):
            await server.broadcast_credential(zone_credential(issued, TAG_A))
        fixture[:] = [Fixture(TAG_A, memo)]
        await server.broadcast_credential(zone_credential(issued, TAG_A))

    @pytest.mark.asyncio
    async def test_accepts_two_payments_settled_in_one_tempo_transaction(self) -> None:
        fixture: list[Fixture] = []
        server = setup(lambda: fixture)
        a, memo_a = await issue(server)
        b, memo_b = await issue(server)
        fixture[:] = [Fixture(TAG_A, memo_a), Fixture(TAG_B, memo_b)]
        await server.broadcast_credential(zone_credential(a, TAG_A))
        await server.broadcast_credential(zone_credential(b, TAG_B))

    @pytest.mark.asyncio
    async def test_rejects_a_withdrawal_bound_to_another_challenge(self) -> None:
        fixture: list[Fixture] = []
        server = setup(lambda: fixture)
        _, memo_a = await issue(server)
        b, _ = await issue(server)
        fixture[:] = [Fixture(TAG_A, memo_a)]
        with pytest.raises(CredentialReplayedError, match="memo is not bound to this challenge"):
            await server.broadcast_credential(zone_credential(b, TAG_A))

    @pytest.mark.asyncio
    async def test_rejects_a_withdrawal_without_an_mpp_memo(self) -> None:
        fixture: list[Fixture] = []
        server = setup(lambda: fixture)
        issued, _ = await issue(server)
        fixture[:] = [Fixture(TAG_A, "0x" + "00" * 32)]
        with pytest.raises(CredentialReplayedError, match="memo is not bound to this challenge"):
            await server.broadcast_credential(zone_credential(issued, TAG_A))

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("overrides", "error"),
        [
            ({"to": OTHER}, "Zone withdrawal not found"),
            ({"amount": 999_999}, "Zone withdrawal not found"),
            ({"token": OTHER_CURRENCY}, "Zone withdrawal not found"),
            ({"callback_success": False}, "Zone withdrawal bounced"),
            ({"event_address": zone_lib.portal_address(4)}, "not settled"),
            ({"in_calldata": False}, "Zone withdrawal not found"),
            ({"gas_limit": 100_000}, "Zone withdrawal not found"),
        ],
        ids=[
            "recipient",
            "amount",
            "currency",
            "bounced",
            "other-portal",
            "missing-calldata",
            "callback",
        ],
    )
    async def test_rejects_a_mismatched_withdrawal(
        self, overrides: dict[str, Any], error: str
    ) -> None:
        fixture: list[Fixture] = []
        server = setup(lambda: fixture)
        issued, memo = await issue(server)
        fixture[:] = [Fixture(TAG_A, memo, **overrides)]
        with pytest.raises(VerificationError, match=error):
            await server.broadcast_credential(zone_credential(issued, TAG_A))

    @pytest.mark.asyncio
    async def test_rejects_a_reverted_settlement_transaction(self) -> None:
        fixture: list[Fixture] = []
        server = setup(lambda: fixture, status="0x0")
        issued, memo = await issue(server)
        fixture[:] = [Fixture(TAG_A, memo)]
        with pytest.raises(PaymentError, match="settlement transaction reverted"):
            await server.broadcast_credential(zone_credential(issued, TAG_A))

    @pytest.mark.asyncio
    async def test_rejects_a_zone_the_challenge_does_not_accept(self) -> None:
        rpc_methods: list[str] = []
        server = setup(rpc_methods=rpc_methods)
        issued, _ = await issue(server)
        with pytest.raises(VerificationError, match="Zone is not accepted for this challenge"):
            await server.broadcast_credential(zone_credential(issued, TAG_A, zone_id=4))
        assert "eth_getTransactionReceipt" not in rpc_methods

    @pytest.mark.asyncio
    async def test_accepts_a_withdrawal_from_any_zone_when_zones_is_true(self) -> None:
        fixture: list[Fixture] = []
        server = setup_any_zone(lambda: fixture)
        issued, memo = await issue(server)
        assert issued.request["methodDetails"]["zones"] is True
        fixture[:] = [Fixture(TAG_A, memo)]
        receipt = await server.broadcast_credential(zone_credential(issued, TAG_A))
        assert receipt.status == "success"

    @pytest.mark.asyncio
    async def test_checks_the_portal_of_the_zone_the_credential_names(self) -> None:
        fixture: list[Fixture] = []
        server = setup_any_zone(lambda: fixture)
        issued, memo = await issue(server)
        fixture[:] = [Fixture(TAG_A, memo)]
        # The settlement came from Zone 3's portal, not Zone 4's.
        with pytest.raises(VerificationError, match="Zone withdrawal not settled"):
            await server.broadcast_credential(zone_credential(issued, TAG_A, zone_id=4))

    @pytest.mark.asyncio
    @pytest.mark.parametrize("zone_id", [0, -1, 1.5, 2**32])
    async def test_rejects_invalid_zone_ids(self, zone_id: Any) -> None:
        rpc_methods: list[str] = []
        server = setup(zones=[ZONE_ID], rpc_methods=rpc_methods)
        issued, _ = await issue(server)
        with pytest.raises(PaymentError):
            await server.broadcast_credential(zone_credential(issued, TAG_A, zone_id=zone_id))
        assert "eth_getTransactionReceipt" not in rpc_methods

    @pytest.mark.asyncio
    @pytest.mark.parametrize("zone_id", [0, 2**32])
    async def test_intent_verify_rejects_invalid_zone_ids_as_verification_errors(
        self, zone_id: Any
    ) -> None:
        server = setup_any_zone()
        issued, _ = await issue(server)
        credential = zone_credential(issued, TAG_A, zone_id=zone_id)
        with pytest.raises(VerificationError, match="Invalid zone credential payload"):
            await ChargeIntent(rpc_url="https://rpc.test").verify(credential, issued.request)

    @pytest.mark.asyncio
    async def test_rejects_zone_credentials_for_pull_only_challenges(self) -> None:
        rpc_methods: list[str] = []
        server = setup(rpc_methods=rpc_methods)
        issued, _ = await issue(server, supported_modes=["pull"])
        with pytest.raises(VerificationError, match="Zone credentials are not supported"):
            await server.broadcast_credential(zone_credential(issued, TAG_A))
        assert "eth_getTransactionReceipt" not in rpc_methods

    @pytest.mark.asyncio
    async def test_rejects_zone_credentials_for_split_payments(self) -> None:
        server = setup()
        issued, _ = await issue(server, splits=[{"amount": "100000", "recipient": OTHER}])
        with pytest.raises(VerificationError, match="do not support split payments"):
            await server.broadcast_credential(zone_credential(issued, TAG_A))

    @pytest.mark.parametrize("zones", [[], [0], ["3"], "3", False])
    def test_rejects_invalid_zones_option(self, zones: Any) -> None:
        with pytest.raises(ValueError):
            tempo_server.charge(recipient=MERCHANT, currencies=[CURRENCY], zones=zones)


def failing_l1() -> httpx.AsyncClient:
    def handle(method: str, params: list[Any]) -> Any:
        if method == "eth_chainId":
            return hex(MODERATO)
        raise RuntimeError(f"l1: {method}")

    return rpc_client(handle)


def used_zone(chain_id: int = 1_424_310_003, calls: list[str] | None = None, **options: Any):
    """A Zone whose every RPC call fails loudly, to show whether the client used it."""

    async def respond(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(json.loads(request.content)["method"])
        await asyncio.sleep(0.01)
        raise RuntimeError("zone used")

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    return Zone(rpc_url="https://zone.test", chain_id=chain_id, http_client=client, **options)


def payer_method(zone: Zone, l1: httpx.AsyncClient | None = None, **options: Any):
    return _tempo_method(
        account=PAYER,
        chain_id=MODERATO,
        currency=CURRENCY,
        zone=zone,
        http_client=l1 or failing_l1(),
        **options,
    )


async def zone_challenge(zones: list[int] | Literal[True], **request: Any) -> Challenge:
    server = setup_any_zone() if zones is True else setup(zones=zones)
    issued, _ = await issue(server, **request)
    return issued


async def error_of(awaitable: Any) -> BaseException:
    try:
        await awaitable
    except BaseException as error:
        return error
    raise AssertionError("expected an error")


class TestClientZoneSelection:
    @pytest.mark.asyncio
    async def test_pays_from_a_zone_on_the_challenge_chain(self) -> None:
        method = payer_method(used_zone())
        with pytest.raises(RuntimeError, match="zone used"):
            await method.create_credential(await zone_challenge([3]))

    @pytest.mark.asyncio
    async def test_pays_from_a_zone_when_the_challenge_accepts_any_zone(self) -> None:
        method = payer_method(used_zone())
        with pytest.raises(RuntimeError, match="zone used"):
            await method.create_credential(await zone_challenge(True))

    @pytest.mark.asyncio
    async def test_pays_on_tempo_when_the_challenge_does_not_accept_the_zone(self) -> None:
        method = payer_method(used_zone(1_424_310_004))
        error = await error_of(method.create_credential(await zone_challenge([3])))
        assert "zone used" not in str(error)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("expires_in", [30, 65])
    async def test_pays_on_tempo_when_the_withdrawal_could_not_settle_before_expiry(
        self, expires_in: int
    ) -> None:
        # 65 s is more than the settlement timeout, but leaves no time to send the withdrawal.
        method = payer_method(used_zone(settlement_timeout=60))
        issued = await zone_challenge([3], expires_in=timedelta(seconds=expires_in))
        error = await error_of(method.create_credential(issued))
        assert "zone used" not in str(error)

    @pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -1])
    def test_rejects_an_invalid_settlement_timeout(self, timeout: float) -> None:
        with pytest.raises(ValueError, match="settlement_timeout"):
            used_zone(settlement_timeout=timeout)

    def test_rejects_a_zone_id_that_does_not_match_the_zone_chain(self) -> None:
        with pytest.raises(ValueError, match="does not match Zone 3"):
            used_zone(zone_id=4)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("zone_chain_id", "request_options", "method_options"),
        [
            (421_700_003, {}, {}),
            (1_424_310_003, {"supported_modes": ["pull"]}, {}),
            (1_424_310_003, {}, {"mode": "pull"}),
            (1_424_310_003, {"splits": [{"amount": "100000", "recipient": MERCHANT}]}, {}),
        ],
        ids=["other-parent-chain", "pull-only-challenge", "pull-client", "splits"],
    )
    async def test_pays_on_tempo(
        self, zone_chain_id: int, request_options: dict[str, Any], method_options: dict[str, Any]
    ) -> None:
        method = payer_method(used_zone(zone_chain_id), **method_options)
        error = await error_of(
            method.create_credential(await zone_challenge([3], **request_options))
        )
        assert "zone used" not in str(error)

    @pytest.mark.asyncio
    async def test_shares_one_withdrawal_between_concurrent_calls(self) -> None:
        calls: list[str] = []
        method = payer_method(used_zone(calls=calls))
        issued = await zone_challenge([3])
        results = await asyncio.gather(
            method.create_credential(issued),
            method.create_credential(issued),
            return_exceptions=True,
        )
        assert all(isinstance(result, RuntimeError) for result in results)
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_reads_the_zone_chain_id_when_not_configured(self) -> None:
        calls: list[str] = []
        zone = Zone(
            rpc_url="https://zone.test",
            http_client=rpc_client(lambda method, params: hex(421_700_003), calls),
        )
        method = payer_method(zone)
        # A mainnet Zone does not settle on Moderato, so the client pays on Tempo.
        error = await error_of(method.create_credential(await zone_challenge([3])))
        assert calls == ["eth_chainId"]
        assert "l1:" in str(error)


REVERTED_RECEIPT = {"status": "0x0", "transactionHash": "0x" + "22" * 32, "logs": []}


def failing_zone(calls: list[str], failing: str) -> Zone:
    """A Zone that prepares and signs withdrawals, then fails to send them or earlier."""
    sent = False

    def handle(method: str, params: list[Any]) -> Any:
        nonlocal sent
        if method == "eth_call":
            return "0x" + "00" * 32
        if failing == "prepare" or sent:
            raise RuntimeError("connection lost")
        if method == "eth_sendRawTransactionSync" and failing == "revert":
            return REVERTED_RECEIPT
        if method == "eth_sendRawTransactionSync":
            sent = True
            raise RuntimeError("connection lost")
        return "0x1"

    return Zone(
        rpc_url="https://zone.test", chain_id=1_424_310_003, http_client=rpc_client(handle, calls)
    )


class TestClientZoneWithdrawalFailures:
    @pytest.mark.asyncio
    async def test_does_not_withdraw_again_after_an_unknown_outcome(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tempo_client, "_ZONE_RECEIPT_RECOVERY_TIMEOUT", 0.0)
        calls: list[str] = []
        method = payer_method(failing_zone(calls, "send"))
        issued = await zone_challenge([3])
        error = await error_of(method.create_credential(issued))
        assert "Zone withdrawal outcome is unknown: transaction 0x" in str(error)
        assert "eth_sendRawTransactionSync" in calls
        assert "eth_getTransactionReceipt" in calls
        sent = len(calls)
        with pytest.raises(tempo_client.TransactionError, match="outcome is unknown"):
            await method.create_credential(issued)
        assert len(calls) == sent

    @pytest.mark.asyncio
    async def test_retries_a_withdrawal_that_reverted(self) -> None:
        calls: list[str] = []
        method = payer_method(failing_zone(calls, "revert"))
        issued = await zone_challenge([3])
        for _ in range(2):
            with pytest.raises(tempo_client.TransactionError, match="reverted"):
                await method.create_credential(issued)
        assert calls.count("eth_sendRawTransactionSync") == 2

    @pytest.mark.asyncio
    async def test_retries_a_withdrawal_that_failed_before_it_was_sent(self) -> None:
        calls: list[str] = []
        method = payer_method(failing_zone(calls, "prepare"))
        issued = await zone_challenge([3])
        error = await error_of(method.create_credential(issued))
        assert "outcome is unknown" not in str(error)
        sent = len(calls)
        await error_of(method.create_credential(issued))
        assert len(calls) > sent
        assert "eth_sendRawTransactionSync" not in calls


def requested_log(sender: str, fallback_nonce: int, memo: str) -> dict[str, Any]:
    data = encode(
        list(zone_lib.REQUESTED_DATA_TYPES),
        [CURRENCY, MERCHANT, 1_000_000, 0, bytes.fromhex(memo[2:]), 0, fallback_nonce, b"", b""],
    )
    return {
        "address": zone_lib.ZONE_OUTBOX,
        "topics": [zone_lib.WITHDRAWAL_REQUESTED_TOPIC, word("0x01"), word(sender)],
        "data": "0x" + data.hex(),
    }


class TestClientZonePayment:
    """A Zone payment end to end against mocked Zone and Tempo RPCs."""

    @pytest.mark.asyncio
    async def test_pays_resumes_and_is_accepted(self) -> None:
        zone_tx = "0x" + "cd" * 32
        sent: list[str] = []
        withdrawal: dict[str, Any] = {}

        def zone_rpc(method: str, params: list[Any]) -> Any:
            if method == "eth_call":
                assert params[0]["to"] == zone_lib.ZONE_OUTBOX
                return "0x" + "00" * 31 + "0a"
            if method in ("eth_estimateGas", "eth_gasPrice"):
                return "0x1"
            if method == "eth_sendRawTransactionSync":
                from eth_abi.abi import decode
                from pytempo import TempoTransaction  # pyright: ignore[reportMissingTypeStubs]

                sent.append(params[0])
                tx = TempoTransaction.decode(bytes.fromhex(params[0][2:]))
                approve, request = tx.calls
                assert bytes(request.to).hex() == zone_lib.ZONE_OUTBOX[2:]
                assert int(approve.data.hex()[-64:], 16) == 1_000_000 + 10
                fields = decode(
                    [
                        "address",
                        "address",
                        "uint128",
                        "bytes32",
                        "uint64",
                        "address",
                        "bytes",
                        "bytes",
                    ],
                    request.data[4:],
                )
                withdrawal["memo"] = "0x" + fields[3].hex()
                assert fields[1].lower() == MERCHANT and fields[2] == 1_000_000 and fields[4] == 0
                return {
                    "status": "0x1",
                    "transactionHash": zone_tx,
                    "logs": [requested_log(PAYER.address, 9, withdrawal["memo"])],
                }
            raise AssertionError(method)

        expected_tag = zone_lib.sender_tag(PAYER.address, zone_tx, 9)
        settled = False

        def tempo_l1(method: str, params: list[Any]) -> Any:
            if method == "eth_chainId":
                return hex(MODERATO)
            if method == "eth_blockNumber":
                return "0x20"
            if method == "eth_getLogs":
                (query,) = params
                assert query["address"] == PORTAL
                assert query["topics"] == [
                    zone_lib.WITHDRAWAL_PROCESSED_TOPIC,
                    word(MERCHANT),
                    expected_tag,
                ]
                return [processed_log(sender_tag=expected_tag)] if settled else []
            raise AssertionError(method)

        zone = Zone(
            rpc_url="https://zone.test",
            chain_id=1_424_310_003,
            # 0 still checks Tempo once per attempt.
            settlement_timeout=0,
            http_client=rpc_client(zone_rpc),
        )
        l1_calls: list[str] = []
        method = payer_method(zone, rpc_client(tempo_l1, l1_calls))
        fixture: list[Fixture] = []
        server = setup(lambda: fixture)
        issued, _ = await issue(server)

        pending = await error_of(method.create_credential(issued))
        assert isinstance(pending, ZoneSettlementPendingError)
        assert (pending.challenge_id, pending.sender_tag, pending.zone_id) == (
            issued.id,
            expected_tag,
            ZONE_ID,
        )
        assert isinstance(pending.__cause__, TimeoutError)

        assert l1_calls.count("eth_getLogs") == 1

        # The retry finds the same withdrawal settled instead of paying again.
        settled = True
        credential = await method.create_credential(issued)
        assert len(sent) == 1
        assert credential.payload == {
            "hash": SETTLEMENT_HASH,
            "senderTag": expected_tag,
            "type": "zone",
            "zoneId": ZONE_ID,
        }
        assert method.transaction_hash(credential) == SETTLEMENT_HASH

        fixture[:] = [Fixture(expected_tag, withdrawal["memo"])]
        receipt = await server.broadcast_credential(credential)
        assert receipt.reference == SETTLEMENT_HASH

    def test_charge_accepts_a_zone(self) -> None:
        method = tempo_client.charge(account=PAYER, zone=used_zone())
        assert method is not None


def zone_rpc_client(handle: Callable[[str, list[Any]], Any]) -> httpx.AsyncClient:
    """An httpx client whose async `handle` returns a JSON-RPC response body or raises."""

    async def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        reply = await handle(body["method"], body["params"])
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], **reply})

    return httpx.AsyncClient(transport=httpx.MockTransport(respond))


def preparing_zone(calls: list[str], send: Callable[[], Any]) -> Zone:
    """A Zone that prepares a withdrawal, then answers its send with `send()`."""

    async def handle(method: str, params: list[Any]) -> dict[str, Any]:
        calls.append(method)
        if method == "eth_call":
            return {"result": "0x" + "00" * 32}
        if method == "eth_sendRawTransactionSync":
            return await send()
        return {"result": "0x1"}

    return Zone(
        rpc_url="https://zone.test", chain_id=1_424_310_003, http_client=zone_rpc_client(handle)
    )


class TestClientZoneCancellation:
    @pytest.mark.asyncio
    async def test_does_not_withdraw_when_every_caller_cancelled_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        preparing = asyncio.Event()
        release = asyncio.Event()
        get_zone_chain_id = tempo_client.TempoMethod._get_zone_chain_id

        async def slow_chain_id(self: Any, zone: Zone) -> int:
            if not release.is_set():
                preparing.set()
                await release.wait()
            return await get_zone_chain_id(self, zone)

        monkeypatch.setattr(tempo_client.TempoMethod, "_get_zone_chain_id", slow_chain_id)

        async def send() -> dict[str, Any]:
            return {"error": {"code": -32000, "message": "insufficient funds"}}

        method = payer_method(preparing_zone(calls, send))
        issued = await zone_challenge([3])
        caller = asyncio.ensure_future(method.create_credential(issued))
        await preparing.wait()
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        release.set()
        for _ in range(20):
            await asyncio.sleep(0)
        assert "eth_sendRawTransactionSync" not in calls
        # The cancelled withdrawal sent nothing, so a later call may pay.
        with pytest.raises(tempo_client.TransactionError, match="submission failed"):
            await method.create_credential(issued)
        assert calls.count("eth_sendRawTransactionSync") == 1

    @pytest.mark.asyncio
    async def test_reports_an_unknown_outcome_when_cancelled_after_submission(self) -> None:
        from eth_hash.auto import keccak

        calls: list[str] = []
        sending = asyncio.Event()
        sent: list[str] = []

        async def send() -> dict[str, Any]:
            sending.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        zone = preparing_zone(calls, send)
        method = payer_method(zone)
        original = method._request_zone_withdrawal  # pyright: ignore[reportPrivateUsage]

        async def recording(challenge: Challenge, state: Any) -> str:
            report = state.on_submission
            state.on_submission = lambda raw: (sent.append(raw), report(raw))
            return await original(challenge, state)

        method._request_zone_withdrawal = recording  # pyright: ignore[reportPrivateUsage]
        issued = await zone_challenge([3])
        caller = asyncio.ensure_future(method.create_credential(issued))
        await sending.wait()
        caller.cancel()
        error = await error_of(caller)
        assert isinstance(error, PaymentOutcomeUnknownError)
        assert error.transaction_hash == "0x" + keccak(bytes.fromhex(sent[0][2:])).hex()


class TestClientZoneWithdrawalFee:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("options", "cap"),
        [
            ({"max_atomic_amount": 1_000_000}, "max_atomic_amount"),
            ({"max_amount": "1", "max_amount_decimals": 6}, "max_amount"),
        ],
    )
    async def test_refuses_a_fee_that_takes_the_withdrawal_over_the_amount_cap(
        self, options: dict[str, Any], cap: str
    ) -> None:
        calls: list[str] = []

        async def handle(method: str, params: list[Any]) -> dict[str, Any]:
            calls.append(method)
            # The outbox charges 1 base unit on top of the 1_000_000 the challenge asks.
            return {"result": hex(1) if method == "eth_call" else "0x1"}

        zone = Zone(
            rpc_url="https://zone.test",
            chain_id=1_424_310_003,
            http_client=zone_rpc_client(handle),
        )
        method = payer_method(zone, **options)
        issued = await zone_challenge([3])
        with pytest.raises(ValueError, match=f"plus its fee exceeds {cap}"):
            await method.create_credential(issued)
        assert "eth_estimateGas" not in calls
        assert "eth_sendRawTransactionSync" not in calls


class TestClientZoneValidBefore:
    def test_leaves_time_to_settle_and_present_the_credential(self) -> None:
        import time
        from datetime import UTC, datetime

        expires = datetime.fromtimestamp(time.time() + 50, UTC).isoformat()
        valid_before = tempo_client._zone_valid_before(  # pyright: ignore[reportPrivateUsage]
            expires, 20
        )
        latest = datetime.fromisoformat(expires).timestamp() - 20 - 15
        assert latest - 1 <= valid_before <= latest
        # Without an expiry, the usual expiring-nonce window applies.
        assert tempo_client._zone_valid_before(  # pyright: ignore[reportPrivateUsage]
            None, 20
        ) == pytest.approx(time.time() + tempo_client.EXPIRING_NONCE_VALID_BEFORE_SECS, abs=2)

    @pytest.mark.asyncio
    async def test_refuses_a_withdrawal_that_could_no_longer_settle_in_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The challenge passed the expiry check, but preparing took too long.
        monkeypatch.setattr(tempo_client, "_zone_settles_before_expiry", lambda *_: True)
        calls: list[str] = []

        async def send() -> dict[str, Any]:
            raise AssertionError("unreachable")

        method = payer_method(preparing_zone(calls, send))
        issued = await zone_challenge([3], expires_in=timedelta(seconds=30))
        with pytest.raises(tempo_client.TransactionError, match="expires too soon"):
            await method.create_credential(issued)
        assert "eth_sendRawTransactionSync" not in calls


class TestClientZoneSubmissionFailures:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "failure",
        [
            httpx.ConnectError("refused"),
            httpx.PoolTimeout("pool"),
            {"error": {"code": -32000, "message": "insufficient funds for gas"}},
        ],
        ids=["connect", "pool", "rpc-insufficient-funds"],
    )
    async def test_retries_a_withdrawal_the_zone_never_took(self, failure: Any) -> None:
        calls: list[str] = []

        async def send() -> dict[str, Any]:
            if isinstance(failure, Exception):
                raise failure
            return failure

        method = payer_method(preparing_zone(calls, send))
        issued = await zone_challenge([3])
        for _ in range(2):
            with pytest.raises(tempo_client.TransactionError, match="submission failed"):
                await method.create_credential(issued)
        assert calls.count("eth_sendRawTransactionSync") == 2
        assert "eth_getTransactionReceipt" not in calls

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "failure",
        [
            httpx.ReadTimeout("slow"),
            {"error": {"code": 4, "message": "transaction pooled, not confirmed"}},
        ],
        ids=["read-timeout", "rpc-sync-timeout"],
    )
    async def test_does_not_withdraw_again_after_an_ambiguous_failure(
        self, failure: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tempo_client, "_ZONE_RECEIPT_RECOVERY_TIMEOUT", 0.0)
        calls: list[str] = []

        async def send() -> dict[str, Any]:
            if isinstance(failure, Exception):
                raise failure
            return failure

        method = payer_method(preparing_zone(calls, send))
        issued = await zone_challenge([3])
        for _ in range(2):
            with pytest.raises(tempo_client.TransactionError, match="outcome is unknown"):
                await method.create_credential(issued)
        assert calls.count("eth_sendRawTransactionSync") == 1


class TestWaitForSettlement:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("slow", ["eth_blockNumber", "eth_getLogs"])
    @pytest.mark.parametrize("polls", [0, 1])
    async def test_bounds_slow_rpc_calls(
        self, slow: str, polls: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A stalled first search is bounded by FIRST_SCAN_TIMEOUT, a later one by the timeout.
        monkeypatch.setattr(zone_lib, "FIRST_SCAN_TIMEOUT", 0.1)
        monkeypatch.setattr(zone_lib, "POLLING_INTERVAL", 0.01)
        seen = {"eth_blockNumber": 0, "eth_getLogs": 0}

        async def handle(method: str, params: list[Any]) -> dict[str, Any]:
            seen[method] += 1
            if method == slow and seen[method] > polls:
                await asyncio.sleep(30)
            return {"result": "0x20" if method == "eth_blockNumber" else []}

        started = asyncio.get_running_loop().time()
        with pytest.raises(TimeoutError, match="did not settle"):
            await zone_lib.wait_for_settlement(
                "https://tempo.test",
                portal=PORTAL,
                sender_tag=TAG_A,
                timeout=0.1 * polls,
                client=zone_rpc_client(handle),
            )
        assert asyncio.get_running_loop().time() - started < 5

    @pytest.mark.asyncio
    @pytest.mark.parametrize("settled", [True, False])
    async def test_a_zero_timeout_checks_once(self, settled: bool) -> None:
        calls: list[str] = []

        def handle(method: str, params: list[Any]) -> Any:
            if method == "eth_blockNumber":
                return "0x20"
            return [processed_log(sender_tag=TAG_A)] if settled else []

        wait = zone_lib.wait_for_settlement(
            "https://tempo.test",
            portal=PORTAL,
            sender_tag=TAG_A,
            timeout=0,
            client=rpc_client(handle, calls),
        )
        if settled:
            assert await wait == SETTLEMENT_HASH
        else:
            with pytest.raises(TimeoutError, match="did not settle"):
                await wait
        assert calls == ["eth_blockNumber", "eth_getLogs"]


class TestClientZoneResolution:
    @pytest.mark.asyncio
    async def test_pays_on_tempo_when_the_zone_rpc_is_unreachable(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("zone down")

        zone = Zone(
            rpc_url="https://zone.test",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(unreachable)),
        )
        method = payer_method(zone)
        error = await error_of(method.create_credential(await zone_challenge([3])))
        assert "l1:" in str(error)


class TestClientZoneCancelledAfterSettlement:
    @pytest.mark.asyncio
    async def test_a_retry_resumes_a_settled_withdrawal_no_caller_received(self) -> None:
        calls: list[str] = []

        async def send() -> dict[str, Any]:
            return {
                "result": {
                    "status": "0x1",
                    "transactionHash": "0x" + "cd" * 32,
                    "logs": [requested_log(PAYER.address, 9, "0x" + "00" * 32)],
                }
            }

        settling = asyncio.Event()
        release = asyncio.Event()

        def tempo_l1(method: str, params: list[Any]) -> Any:
            if method == "eth_chainId":
                return hex(MODERATO)
            if method == "eth_blockNumber":
                return "0x20"
            if method == "eth_getLogs":
                return [processed_log(sender_tag=params[0]["topics"][2])]
            raise AssertionError(method)

        l1 = rpc_client(tempo_l1)
        original_post = l1.post

        async def slow_post(*args: Any, **kwargs: Any) -> httpx.Response:
            if kwargs["json"]["method"] == "eth_getLogs":
                settling.set()
                await release.wait()
            return await original_post(*args, **kwargs)

        l1.post = slow_post  # type: ignore[method-assign]
        method = payer_method(preparing_zone(calls, send), l1)
        issued = await zone_challenge([3])
        caller = asyncio.ensure_future(method.create_credential(issued))
        await settling.wait()
        caller.cancel()
        assert isinstance(await error_of(caller), PaymentOutcomeUnknownError)
        release.set()
        for _ in range(50):
            await asyncio.sleep(0)
        credential = await method.create_credential(issued)
        assert credential.payload["type"] == "zone"
        assert calls.count("eth_sendRawTransactionSync") == 1


class TestZoneCoverage:
    """Edge cases of the Zone helpers."""

    def test_portal_address_accepts_zone_chain_ids(self) -> None:
        portal = zone_lib.portal_address(3)
        assert zone_lib.portal_address(4_217_000_003) == portal
        assert zone_lib.portal_address(421_700_003) == portal
        assert zone_lib.portal_address(1_424_310_003) == portal

    def test_find_processed_event_skips_malformed_logs(self) -> None:
        good = processed_log(sender_tag=TAG_A)
        logs = [
            "junk",
            {**good, "topics": good["topics"][:2]},
            {**good, "data": None},
            {**good, "data": "0x1234"},
        ]
        assert zone_lib.find_processed_event(logs, portal=PORTAL, sender_tag=TAG_A) is None
        event = zone_lib.find_processed_event([*logs, good], portal=PORTAL, sender_tag=TAG_A)
        assert event is not None and event.amount == 1_000_000

    def test_find_withdrawal_skips_other_and_undecodable_calls(self) -> None:
        selector = "0x" + zone_lib.PROCESS_WITHDRAWALS_SELECTOR
        calls = [(OTHER, selector), (PORTAL, selector + "00")]
        assert zone_lib.find_withdrawal(calls, portal=PORTAL, sender_tag=TAG_A) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("timeout", [float("nan"), -1])
    async def test_wait_for_settlement_rejects_an_invalid_timeout(self, timeout: float) -> None:
        with pytest.raises(ValueError, match="finite, non-negative"):
            await zone_lib.wait_for_settlement(
                "https://tempo.test", portal=PORTAL, sender_tag=TAG_A, timeout=timeout
            )

    @pytest.mark.asyncio
    async def test_wait_for_settlement_skips_logs_without_a_hash(self) -> None:
        def handle(method: str, params: list[Any]) -> Any:
            return "0x20" if method == "eth_blockNumber" else ["junk", {"transactionHash": 1}]

        with pytest.raises(TimeoutError, match="did not settle"):
            await zone_lib.wait_for_settlement(
                "https://tempo.test",
                portal=PORTAL,
                sender_tag=TAG_A,
                timeout=0,
                client=rpc_client(handle),
            )

    @pytest.mark.asyncio
    async def test_wait_for_settlement_stops_when_the_deadline_passed_during_a_poll(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The clock reads 0 through the first search and its poll check, then 5.
        readings = iter([0.0, 0.0, 0.0, 0.0])

        class Clock:
            @staticmethod
            def monotonic() -> float:
                return next(readings, 5.0)

        monkeypatch.setattr(zone_lib, "time", Clock)
        monkeypatch.setattr(zone_lib, "POLLING_INTERVAL", 0.0)
        calls: list[str] = []

        def handle(method: str, params: list[Any]) -> Any:
            return "0x20" if method == "eth_blockNumber" else []

        with pytest.raises(TimeoutError, match="did not settle"):
            await zone_lib.wait_for_settlement(
                "https://tempo.test",
                portal=PORTAL,
                sender_tag=TAG_A,
                timeout=1,
                client=rpc_client(handle, calls),
            )
        assert calls == ["eth_blockNumber", "eth_getLogs"]


def scripted_zone(calls: list[str], **answers: Any) -> Zone:
    """A Zone answering each JSON-RPC method from answers (a value, or a callable)."""
    defaults: dict[str, Any] = {
        "eth_call": "0x" + "00" * 32,
        "eth_estimateGas": "0x1",
        "eth_gasPrice": "0x1",
        "eth_getTransactionReceipt": None,
        "eth_chainId": hex(1_424_310_003),
    }

    async def handle(method: str, params: list[Any]) -> dict[str, Any]:
        calls.append(method)
        answer: Any = answers.get(method, defaults.get(method))
        if callable(answer):
            answer = answer()
        if isinstance(answer, BaseException):
            raise answer
        # A JSON-RPC error answers as it is; anything else is the result.
        if isinstance(answer, dict) and "error" in answer:
            return dict[str, Any](answer)
        return {"result": answer}

    return Zone(
        rpc_url="https://zone.test", chain_id=1_424_310_003, http_client=zone_rpc_client(handle)
    )


def settled_l1() -> httpx.AsyncClient:
    def tempo_l1(method: str, params: list[Any]) -> Any:
        if method == "eth_chainId":
            return hex(MODERATO)
        if method == "eth_blockNumber":
            return "0x20"
        if method == "eth_getLogs":
            return [processed_log(sender_tag=params[0]["topics"][2])]
        raise AssertionError(method)

    return rpc_client(tempo_l1)


def sent_receipt(logs: list[Any] | None = None) -> dict[str, Any]:
    return {
        "status": "0x1",
        "transactionHash": "0x" + "cd" * 32,
        "logs": [requested_log(PAYER.address, 9, "0x" + "00" * 32)] if logs is None else logs,
    }


class TestClientZoneCoverage:
    """Edge cases of the client's Zone payment path."""

    def test_zone_options(self) -> None:
        with pytest.raises(ValueError, match="Invalid Zone ID"):
            Zone(rpc_url="https://zone.test", zone_id=0)
        zone = Zone(rpc_url="https://zone.test", zone_id=3, chain_id=1_424_310_003)
        assert zone.zone_id == 3

    def test_settlement_timing_without_an_expiry(self) -> None:
        assert tempo_client._zone_settles_before_expiry(None, 60)  # pyright: ignore[reportPrivateUsage]
        timeout = tempo_client._zone_settlement_timeout  # pyright: ignore[reportPrivateUsage]
        assert timeout(None, None) == zone_lib.DEFAULT_SETTLEMENT_TIMEOUT
        assert timeout(None, 5) == 5

    @pytest.mark.asyncio
    async def test_reads_the_zone_chain_id_once(self) -> None:
        calls: list[str] = []
        from dataclasses import replace

        zone = replace(scripted_zone(calls), chain_id=None)
        method = payer_method(zone)
        for _ in range(2):
            assert await method._get_zone_chain_id(zone) == 1_424_310_003  # pyright: ignore[reportPrivateUsage]
        assert calls == ["eth_chainId"]

    @pytest.mark.asyncio
    async def test_pays_on_tempo_when_the_challenge_names_no_zones(self) -> None:
        from dataclasses import replace

        method = payer_method(used_zone())
        issued = await zone_challenge([3])
        details = {k: v for k, v in issued.request["methodDetails"].items() if k != "zones"}
        bare = replace(issued, request={**issued.request, "methodDetails": details})
        assert await method._zone_payment(bare, MODERATO) is None  # pyright: ignore[reportPrivateUsage]

    @pytest.mark.asyncio
    async def test_requires_an_account(self) -> None:
        method = payer_method(scripted_zone([]))
        method.account = None
        state = tempo_client._ZoneSend()  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(ValueError, match="require an account"):
            await method._request_zone_withdrawal(await zone_challenge([3]), state)  # pyright: ignore[reportPrivateUsage]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("policy", "error"),
        [
            ({"max_fee_per_gas": 0}, "gas-price quote exceeds payer fee policy"),
            ({"max_total_fee": 0}, "exceeds payer total-fee budget"),
        ],
    )
    async def test_refuses_gas_beyond_the_payer_fee_policy(
        self, policy: dict[str, int], error: str
    ) -> None:
        calls: list[str] = []
        method = payer_method(scripted_zone(calls), payer_fee_policy=policy)
        with pytest.raises(tempo_client.TransactionError, match=error):
            await method.create_credential(await zone_challenge([3]))
        assert "eth_sendRawTransactionSync" not in calls

    @pytest.mark.asyncio
    async def test_signs_as_an_access_key_of_the_root_account(self) -> None:
        calls: list[str] = []
        failure = {"error": {"code": -32000, "message": "insufficient funds"}}
        zone = scripted_zone(calls, eth_sendRawTransactionSync=failure)
        method = payer_method(zone, root_account=OTHER)
        with pytest.raises(tempo_client.TransactionError, match="submission failed"):
            await method.create_credential(await zone_challenge([3]))
        assert "eth_sendRawTransactionSync" in calls

    @pytest.mark.asyncio
    async def test_recovers_the_receipt_of_an_ambiguous_send(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(zone_lib, "POLLING_INTERVAL", 0.01)
        receipts = iter([None, sent_receipt()])
        calls: list[str] = []
        zone = scripted_zone(
            calls,
            eth_sendRawTransactionSync=httpx.ReadTimeout("slow"),
            eth_getTransactionReceipt=lambda: next(receipts),
        )
        method = payer_method(zone, settled_l1())
        credential = await method.create_credential(await zone_challenge([3]))
        assert credential.payload["hash"] == SETTLEMENT_HASH
        assert calls.count("eth_getTransactionReceipt") == 2

    @pytest.mark.asyncio
    async def test_fails_when_the_receipt_has_no_withdrawal_request(self) -> None:
        bad = {**requested_log(PAYER.address, 9, "0x" + "00" * 32), "data": "0x1234"}
        zone = scripted_zone([], eth_sendRawTransactionSync=sent_receipt(["junk", bad]))
        method = payer_method(zone)
        with pytest.raises(tempo_client.TransactionError, match="did not emit"):
            await method.create_credential(await zone_challenge([3]))

    @pytest.mark.asyncio
    async def test_fails_when_the_send_returns_no_receipt(self) -> None:
        zone = scripted_zone([], eth_sendRawTransactionSync=None)
        method = payer_method(zone)
        with pytest.raises(tempo_client.TransactionError, match="returned no receipt"):
            await method.create_credential(await zone_challenge([3]))

    @pytest.mark.asyncio
    async def test_concurrent_payments_of_a_challenge_share_one_withdrawal(self) -> None:
        calls: list[str] = []
        method = payer_method(
            scripted_zone(calls, eth_sendRawTransactionSync=sent_receipt()), settled_l1()
        )
        issued = await zone_challenge([3])
        pay = method._create_zone_credential  # pyright: ignore[reportPrivateUsage]
        first, second = await asyncio.gather(pay(issued, ZONE_ID), pay(issued, ZONE_ID))
        assert first.payload == second.payload
        assert calls.count("eth_sendRawTransactionSync") == 1


def zone_intent(
    withdrawals: Callable[[], list[Fixture]], store: MemoryStore | None = None, **failing: Any
) -> ChargeIntent:
    handle = tempo_rpc(withdrawals)

    def answer(method: str, params: list[Any]) -> Any:
        if method in failing:
            raise failing[method]
        return handle(method, params)

    return ChargeIntent(
        chain_id=MODERATO,
        http_client=rpc_client(answer),
        store=MemoryStore() if store is None else store,
    )


class TestServerZoneCoverage:
    """Edge cases of the server's Zone credential checks."""

    @pytest.mark.asyncio
    async def test_broadcast_releases_its_claim_and_rejects_a_replay(self) -> None:
        fixture: list[Fixture] = []
        issued, memo = await issue(setup(lambda: fixture))
        intent = zone_intent(lambda: fixture)
        credential = zone_credential(issued, TAG_A)
        fixture[:] = [Fixture(TAG_A, memo, amount=1)]
        with pytest.raises(VerificationError, match="Zone withdrawal not found"):
            await intent.broadcast(credential, issued.request)
        fixture[:] = [Fixture(TAG_A, memo)]
        receipt = await intent.broadcast(credential, issued.request)
        assert receipt.reference == SETTLEMENT_HASH
        with pytest.raises(CredentialReplayedError, match="already been used"):
            await intent.broadcast(credential, issued.request)

    @pytest.mark.asyncio
    async def test_reserves_nothing_without_a_store(self) -> None:
        from mpp.methods.tempo.schemas import ZoneCredentialPayload

        intent = ChargeIntent(chain_id=MODERATO)
        payload = ZoneCredentialPayload.model_validate(
            {"hash": SETTLEMENT_HASH, "senderTag": TAG_A, "type": "zone", "zoneId": ZONE_ID}
        )
        assert await intent._reserve_zone_withdrawal(payload) is None  # pyright: ignore[reportPrivateUsage]

    @pytest.mark.asyncio
    async def test_fails_internally_when_the_settlement_transaction_cannot_be_read(
        self,
    ) -> None:
        from mpp.errors import InternalPaymentError

        fixture: list[Fixture] = []
        issued, memo = await issue(setup(lambda: fixture))
        fixture[:] = [Fixture(TAG_A, memo)]
        intent = zone_intent(lambda: fixture, eth_getTransactionByHash=RuntimeError("down"))
        with pytest.raises(InternalPaymentError):
            await intent.verify(zone_credential(issued, TAG_A), issued.request)
