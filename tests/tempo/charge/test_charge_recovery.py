"""Port of mppx ``tempo/server/Charge.recovery.test.ts`` (ambiguous broadcast recovery)."""

from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any

import attrs
import httpx
import pytest
from _charge_node import (
    REALM,
    SECRET_KEY,
    build_transaction,
    payer,
    receipt_json,
    sign,
    sponsor,
    transfer_call,
    transfer_logs,
)

from mpp import store as _store
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.errors import CredentialReplayedError, InternalPaymentError, VerificationFailedError
from mpp.server import Mpp
from mpp.tempo import attribution
from mpp.tempo._internal.envelope import deserialize
from mpp.tempo._internal.hexutil import keccak256, to_bytes, to_hex
from mpp.tempo._internal.rpc import (
    RpcClient,
    RpcError,
    RpcTransportError,
    TransactionReceiptTimeoutError,
)
from mpp.tempo.server._charge import charge

RECIPIENT = "0x2222222222222222222222222222222222222222"
CURRENCY = "0x20c0000000000000000000000000000000000001"
OTHER_HASH = "0x" + "12" * 32


@dataclass(frozen=True)
class Failure:
    """A broadcast failure and how to recognize it once raised by the server."""

    kind: str
    code: int | None = None
    message: str = ""
    status: int | None = None

    def raise_(self, request: httpx.Request) -> Any:
        match self.kind:
            case "rpc":
                raise RpcError(self.code or -32000, self.message)
            case "http":
                return httpx.Response(self.status or 500, text="error")
            case "timeout":
                raise httpx.ReadTimeout("timed out", request=request)
            case "aborted":
                raise TimeoutError("The operation was aborted.")
            case "network":
                raise httpx.ConnectError("socket hang up", request=request)
            case "socket":
                raise httpx.RemoteProtocolError("socket closed", request=request)
        raise AssertionError(self.kind)

    def matches(self, error: BaseException) -> bool:
        cause: BaseException | None = error
        while cause is not None:
            if self.kind == "rpc" and isinstance(cause, RpcError):
                return cause.code == self.code and cause.message == self.message
            if self.kind == "http" and isinstance(cause, RpcTransportError):
                return cause.status == self.status
            if self.kind in ("timeout", "network", "socket") and isinstance(
                cause, RpcTransportError
            ):
                return cause.status is None
            if self.kind == "aborted" and isinstance(cause, TimeoutError):
                return True
            cause = cause.__cause__
        return False


ALREADY_KNOWN = Failure("rpc", -32000, "already known")
KNOWN_TRANSACTION = Failure("rpc", -32000, "known transaction: 0x12")
SYNC_TIMEOUT = Failure("rpc", 4, "Transaction was added to the mempool but not confirmed")
TRANSPORT_TIMEOUT = Failure("timeout")
ABORTED = Failure("aborted")
NETWORK_FAILURE = Failure("network")
GATEWAY = Failure("http", status=502)
SOCKET_CLOSED = Failure("socket")
METHOD_NOT_FOUND = Failure("rpc", -32601, "method not found")
INVALID_PARAMS = Failure("rpc", -32602, "invalid params")
INSUFFICIENT_FUNDS = Failure("rpc", -32000, "insufficient funds for gas * price + value")
INVALID_SIGNATURE = Failure("rpc", -32000, "invalid signature")
RATE_LIMITED = Failure("http", status=429)
UNKNOWN_TYPE = Failure("rpc", -32000, "unknown transaction type")
HANG = Failure("hang")


@dataclass
class Setup:
    server: Mpp
    credential: str
    signature: str
    store: Any
    state: dict[str, Any] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    lookup_hashes: list[str] = field(default_factory=list)
    sync_params: list[Any] = field(default_factory=list)
    successes: list[Any] = field(default_factory=list)

    async def broadcast(self) -> Any:
        return await self.server.broadcast_credential(self.credential)

    @property
    def final_hash(self) -> str:
        return self.state["final_hash"]

    @property
    def sends(self) -> int:
        return sum(method.startswith("eth_sendRawTransaction") for method in self.calls)

    @property
    def signature_hash_key(self) -> str:
        return f"mppx:charge:{to_hex(keccak256(to_bytes(self.signature)))}"


async def setup(
    *,
    sponsored: bool,
    error: Failure = GATEWAY,
    confirmation_timeout_ms: int = 200,
    valid_for: int = 25,
    wait_for_confirmation: bool = True,
) -> Setup:
    state: dict[str, Any] = {"outcome": "normal", "gate": None, "memo": None, "final_hash": None}
    calls: list[str] = []
    lookups: list[str] = []
    sync_params: list[Any] = []
    payer_address = payer().address

    def receipt() -> dict[str, Any]:
        outcome = state["outcome"]
        transaction_hash = OTHER_HASH if outcome == "wrong-hash" else state["final_hash"]
        log = transfer_logs(
            CURRENCY,
            payer_address,
            RECIPIENT,
            1 if outcome == "wrong-transfer" else 1_000_000,
            state["memo"],
            0,
        )[1]
        log["logIndex"] = "0x0"
        return receipt_json(
            transaction_hash=transaction_hash,
            sender=payer_address,
            logs=[log],
            status="0x0" if outcome == "reverted" else "0x1",
        )

    async def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method, params = body["method"], body.get("params", [])
        calls.append(method)
        outcome = state["outcome"]

        def result(value: Any) -> httpx.Response:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": value})

        def rpc_error(code: int, message: str) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": code, "message": message},
                },
            )

        try:
            if method == "eth_chainId":
                return result(hex(42431))
            if method == "eth_call":
                return result("0x")
            if method == "eth_getBlockByNumber" and "block_time" in state:
                return result({"number": "0x1", "timestamp": hex(state["block_time"])})
            if method in ("eth_sendRawTransaction", "eth_sendRawTransactionSync"):
                state["final_hash"] = to_hex(keccak256(to_bytes(params[0])))
                state.setdefault("sent", []).append(params[0])
                if method == "eth_sendRawTransactionSync":
                    sync_params[:] = params
                if state["gate"] is not None:
                    await state["gate"].wait()
                if outcome in ("normal", "unseen"):
                    return result(
                        state["final_hash"] if method == "eth_sendRawTransaction" else receipt()
                    )
                if error.kind == "hang" and method == "eth_sendRawTransactionSync":
                    await asyncio.Event().wait()
                response = error.raise_(request)
                return response
            if method == "eth_getTransactionReceipt":
                lookups.append(params[0])
                if outcome in ("missing", "expired", "expiring", "unseen"):
                    return result(None)
                if outcome == "pending" and len(lookups) < 3:
                    return result(None)
                if outcome == "lookup-error":
                    return rpc_error(-32000, "Lookup unavailable")
                return result(receipt())
            return rpc_error(-32601, f"Unexpected RPC method: {method}")
        except RpcError as rpc:
            return rpc_error(rpc.code, rpc.message)

    rpc = RpcClient(
        "https://rpc.example.com",
        http=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        polling_interval=0.01,
    )
    store = _store.memory()
    successes: list[Any] = []
    parameters: dict[str, Any] = {}
    if sponsored:
        parameters = {
            "fee_payer": sponsor(),
            "fee_token": CURRENCY,
            "allowed_fee_tokens": [CURRENCY],
        }
    server = Mpp(
        realm=REALM,
        secret_key=SECRET_KEY,
        methods=[
            charge(
                account=RECIPIENT,
                confirmation_timeout_ms=confirmation_timeout_ms,
                currency=CURRENCY,
                get_client=lambda _: rpc,
                on_payment_success=successes.append,
                store=store,
                testnet=True,
                wait_for_confirmation=wait_for_confirmation,
                **parameters,
            )
        ],
    )
    challenge: Challenge = await server.challenge.tempo.charge(amount="1", decimals=6)
    state["memo"] = attribution.encode(challenge_id=challenge.id, server_id=challenge.realm)
    transaction = build_transaction(
        [transfer_call(CURRENCY, RECIPIENT, 1_000_000, state["memo"])],
        valid_for=valid_for,
        fee_payer=sponsored,
    )
    if not sponsored:
        transaction = attrs.evolve(transaction, nonce_key=0)
    signature = sign(payer(), transaction)
    value = Credential(
        challenge=challenge, payload={"signature": signature, "type": "transaction"}
    ).serialize()
    return Setup(
        server=server,
        credential=value,
        signature=signature,
        store=store,
        state=state,
        calls=calls,
        lookup_hashes=lookups,
        sync_params=sync_params,
        successes=successes,
    )


async def expect_replayed(setup_: Setup) -> None:
    with pytest.raises(CredentialReplayedError) as caught:
        await setup_.broadcast()
    assert (
        caught.value.message
        == "Payment verification failed: Transaction hash has already been used."
    )
    assert caught.value.status == 403
    assert caught.value.type == "https://paymentauth.org/problems/verification-failed"


RECOVERY_CASES = [
    ("included", False, "included", GATEWAY),
    ("sponsored", True, "included", GATEWAY),
    ("sponsored pending", True, "pending", SYNC_TIMEOUT),
    ("missing receipt", False, "missing", ALREADY_KNOWN),
    ("lookup error", False, "lookup-error", GATEWAY),
    ("reverted receipt", False, "reverted", GATEWAY),
    ("wrong transfer", False, "wrong-transfer", GATEWAY),
    ("wrong hash", False, "wrong-hash", GATEWAY),
    ("normal broadcast", False, "normal", GATEWAY),
    ("already known", False, "pending", ALREADY_KNOWN),
    ("known transaction", False, "pending", KNOWN_TRANSACTION),
    ("sync timeout", False, "pending", SYNC_TIMEOUT),
    ("transport timeout", False, "pending", TRANSPORT_TIMEOUT),
    ("aborted", False, "pending", ABORTED),
    ("network failure", False, "pending", NETWORK_FAILURE),
    ("gateway error", False, "pending", GATEWAY),
    ("socket closed", False, "pending", SOCKET_CLOSED),
    ("local deadline", False, "pending", HANG),
    ("local deadline missing", False, "missing", HANG),
    ("expired", False, "expired", ALREADY_KNOWN),
    ("expired mined", False, "expired-mined", ALREADY_KNOWN),
    ("expiring", False, "expiring", ALREADY_KNOWN),
    ("method not found", False, "rejected", METHOD_NOT_FOUND),
    ("invalid params", False, "rejected", INVALID_PARAMS),
    ("insufficient funds", False, "rejected", INSUFFICIENT_FUNDS),
    ("invalid signature", False, "rejected", INVALID_SIGNATURE),
    ("rate limited", False, "rejected", RATE_LIMITED),
    ("unknown transaction type", False, "rejected", UNKNOWN_TYPE),
]


@pytest.mark.parametrize(
    ("sponsored", "outcome", "error"),
    [case[1:] for case in RECOVERY_CASES],
    ids=[case[0] for case in RECOVERY_CASES],
)
async def test_synchronous_charge_recovery(sponsored: bool, outcome: str, error: Failure) -> None:
    expiry = outcome in ("expired", "expired-mined", "expiring")
    timeout_ms = 10_000 if expiry else 200
    valid_for = (
        -3 if outcome in ("expired", "expired-mined") else 1 if outcome == "expiring" else 25
    )
    s = await setup(
        sponsored=sponsored, error=error, confirmation_timeout_ms=timeout_ms, valid_for=valid_for
    )
    s.state["outcome"] = outcome
    settled = outcome in ("included", "pending", "normal", "expired-mined")

    if settled:
        receipt = await s.broadcast()
        assert receipt.status == "success"
        assert receipt.reference == s.final_hash
        assert len(s.successes) == 1
    elif outcome in ("missing", "lookup-error", "rejected", "expired", "expiring"):
        started = time.monotonic()
        with pytest.raises(Exception) as caught:  # noqa: PT011
            await s.broadcast()
        if error is HANG:
            assert isinstance(caught.value, TransactionReceiptTimeoutError)
        else:
            assert error.matches(caught.value), repr(caught.value)
        if expiry:
            assert time.monotonic() - started < timeout_ms / 2 / 1000
        assert s.successes == []
    else:
        with pytest.raises(Exception):  # noqa: B017, PT011
            await s.broadcast()
        assert s.successes == []

    assert s.sync_params[1] == math.floor(timeout_ms * 2 / 3)
    polled = outcome not in ("normal", "rejected")
    assert set(s.lookup_hashes) == ({s.final_hash} if polled else set())
    if outcome == "pending":
        assert len(s.lookup_hashes) == 3
    if outcome in ("expired", "expired-mined"):
        assert len(s.lookup_hashes) == 1
    if sponsored:
        assert s.final_hash != to_hex(keccak256(to_bytes(s.signature)))

    if settled:
        await expect_replayed(s)
        assert s.sends == 1
    else:
        # A failed settlement does not consume the credential, so the retry re-broadcasts.
        with pytest.raises(Exception) as retry:  # noqa: PT011
            await s.broadcast()
        assert not isinstance(retry.value, CredentialReplayedError)
        assert s.successes == []
        assert s.sends == 2


@pytest.mark.parametrize(
    ("first", "retry", "sponsored", "wait"),
    [
        ("lookup-error", "included", False, True),
        ("missing", "included", False, True),
        ("lookup-error", "included", True, True),
        ("lookup-error", "normal", False, False),
    ],
    ids=["receipt lookup error", "missing receipt", "sponsored", "optimistic"],
)
async def test_settles_retried_charge_once_after_post_broadcast_failure(
    first: str, retry: str, sponsored: bool, wait: bool
) -> None:
    s = await setup(sponsored=sponsored, wait_for_confirmation=wait)
    gate = asyncio.Event()
    s.state["gate"] = gate
    s.state["outcome"] = first
    in_flight = asyncio.create_task(s.broadcast())
    while s.sends < 1:  # noqa: ASYNC110
        await asyncio.sleep(0.001)
    await expect_replayed(s)
    gate.set()
    with pytest.raises(Exception) as caught:  # noqa: PT011
        await in_flight
    assert GATEWAY.matches(caught.value)
    assert s.successes == []

    s.state["outcome"] = retry
    receipt = await s.broadcast()
    assert receipt.status == "success"
    assert receipt.reference == s.final_hash
    assert len(s.successes) == 1
    await expect_replayed(s)
    assert len(s.successes) == 1
    # A locally sponsored retry reconciles the recorded envelope from its receipt (pympp#323).
    assert s.sends == (1 if sponsored else 2)


# -- pympp#318/#323: reconciling unknown sponsored outcomes -----------------------------------


def recovery_key(s: Setup) -> str:
    return f"mppx:charge:recovery:{to_hex(keccak256(to_bytes(s.signature)))}"


async def unknown_sponsored_submission(s: Setup) -> None:
    s.state["outcome"] = "missing"
    with pytest.raises(Exception) as caught:  # noqa: PT011
        await s.broadcast()
    assert GATEWAY.matches(caught.value)
    record = await s.store.get(recovery_key(s))
    assert record["transaction"] == s.state["sent"][0]


async def test_retry_rebroadcasts_the_original_sponsored_envelope() -> None:
    s = await setup(sponsored=True)
    await unknown_sponsored_submission(s)
    s.state["outcome"] = "unseen"  # not yet visible to receipt lookups; the re-send lands
    receipt = await s.broadcast()
    assert receipt.reference == s.final_hash
    # The retry re-sent the exact envelope this server signed, not a new sponsorship.
    assert s.state["sent"][0] == s.state["sent"][1]
    assert await s.store.get(recovery_key(s)) is None
    await expect_replayed(s)


async def test_retry_reconciles_a_landed_submission_from_its_receipt() -> None:
    s = await setup(sponsored=True)
    await unknown_sponsored_submission(s)
    s.state["outcome"] = "included"
    receipt = await s.broadcast()
    assert receipt.reference == s.final_hash
    assert s.sends == 1
    assert await s.store.get(recovery_key(s)) is None


async def test_retry_under_the_validity_floor_is_not_payable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    s = await setup(sponsored=True)
    await unknown_sponsored_submission(s)
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 12)
    with pytest.raises(InternalPaymentError):
        await s.broadcast()
    assert s.sends == 1
    assert await s.store.get(recovery_key(s)) is not None
    s.state["outcome"] = "included"
    assert (await s.broadcast()).reference == s.final_hash


async def test_retry_after_inclusion_window_without_receipt_is_payable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    s = await setup(sponsored=True)
    await unknown_sponsored_submission(s)
    valid_before = deserialize(s.state["sent"][0]).valid_before
    assert valid_before is not None
    # Chain time is past validBefore and the receipt is still missing: it never landed.
    s.state["block_time"] = valid_before + 5
    monkeypatch.setattr(time, "time", lambda: valid_before + 5)
    with pytest.raises(VerificationFailedError, match="expired before it was included"):
        await s.broadcast()
    assert await s.store.get(recovery_key(s)) is None


@pytest.mark.parametrize("error", [INVALID_SIGNATURE, INSUFFICIENT_FUNDS])
async def test_rejected_submission_retains_no_record(error: Failure) -> None:
    s = await setup(sponsored=True, error=error)
    s.state["outcome"] = "missing"
    with pytest.raises(Exception):  # noqa: B017, PT011
        await s.broadcast()
    assert await s.store.get(recovery_key(s)) is None


async def test_unrecordable_submission_is_not_broadcast(monkeypatch: pytest.MonkeyPatch) -> None:
    s = await setup(sponsored=True)
    update = s.store.update

    async def failing_update(key: str, fn: Any) -> Any:
        if "recovery" in key:
            raise ConnectionError("store down")
        return await update(key, fn)

    monkeypatch.setattr(s.store, "update", failing_update)
    with pytest.raises(InternalPaymentError):
        await s.broadcast()
    assert s.sends == 0


async def test_live_record_is_never_overwritten() -> None:
    from mpp.tempo.server._charge import (
        _create_recovery,  # pyright: ignore[reportPrivateUsage]
    )

    store = _store.memory()
    future = math.floor((time.time() + 60) * 1000)
    assert await _create_recovery(store, "k", "0x76aa", future)
    assert not await _create_recovery(store, "k", "0x76bb", future)
    assert (await store.get("k"))["transaction"] == "0x76aa"
    await store.put("k", {**(await store.get("k")), "expires": 1})
    assert await _create_recovery(store, "k", "0x76bb", future)
