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
            settlement_timeout=0.2,
            http_client=rpc_client(zone_rpc),
        )
        method = payer_method(zone, rpc_client(tempo_l1))
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
    async def test_bounds_slow_rpc_calls_by_the_timeout(self, slow: str) -> None:
        async def handle(method: str, params: list[Any]) -> dict[str, Any]:
            if method == slow:
                await asyncio.sleep(30)
            return {"result": "0x20" if method == "eth_blockNumber" else []}

        started = asyncio.get_running_loop().time()
        with pytest.raises(TimeoutError, match="did not settle"):
            await zone_lib.wait_for_settlement(
                "https://tempo.test",
                portal=PORTAL,
                sender_tag=TAG_A,
                timeout=0.1,
                client=zone_rpc_client(handle),
            )
        assert asyncio.get_running_loop().time() - started < 5


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
