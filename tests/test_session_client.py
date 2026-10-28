"""Tests for the TIP-1034 session client (ports of mppx Runtime, CredentialState, ChannelOps,
ChannelStore, Session, Fetch and SessionManager tests): deposit sizing, challenge policy,
planning and recovery, stores and scope locks, deferred opens and attempt settlement,
management POSTs, top-ups and the manager. Chain access is faked; see
test_session_client_localnet.py for the flow against an mppx server."""

from __future__ import annotations

import asyncio
import base64
import gc
import json
import os
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.client import Mpp
from mpp.client.transport import (
    PaymentTransport,
    _accepted_keywords,  # pyright: ignore[reportPrivateUsage]
    _response_challenges,  # pyright: ignore[reportPrivateUsage]
)
from mpp.errors import PaymentOutcomeUnknownError
from mpp.events import CREDENTIAL_CREATED
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._protocol import (
    ESCROW_ADDRESS,
    ZERO_ADDRESS,
    ChannelDescriptor,
    SignedVoucher,
    VoucherPayload,
    create_session_receipt,
    serialize_session_receipt,
)
from mpp.methods.tempo.session._voucher import verify_voucher
from mpp.methods.tempo.session.client import (
    ChannelEntry,
    SessionManager,
    SessionMethod,
    UncertainFundingError,
    _session,
    _state,
    _store,
    create_channel_store,
    create_json_channel_store,
    session,
    session_manager,
)
from mpp.methods.tempo.session.client._manager import (
    _FetchUse,  # pyright: ignore[reportPrivateUsage]
)
from mpp.methods.tempo.session.client._ops import read_optional_address, resolve_escrow
from mpp.methods.tempo.session.client._session import (
    _acknowledges_open,  # pyright: ignore[reportPrivateUsage]
    _matches_open,  # pyright: ignore[reportPrivateUsage]
    _PendingOpenStore,  # pyright: ignore[reportPrivateUsage]
)
from mpp.methods.tempo.session.client._state import (
    ChannelSink,
    SessionContext,
)
from mpp.methods.tempo.session.client._store import (
    _locks,  # pyright: ignore[reportPrivateUsage]
    _StoreMap,  # pyright: ignore[reportPrivateUsage]
    entry_key,
    persist_channel,
    store_lock,
)
from mpp.runtime import (
    AttemptOutcome,
    ClientMethod,
    CredentialParams,
    PaymentAttempt,
    PaymentRuntime,
)

PAYEE = "0x" + "11" * 20
TOKEN = "0x20c0000000000000000000000000000000000000"
CUSTOM_ESCROW = "0x" + "22" * 20
CHAIN_ID = 4217
ACCOUNT = TempoAccount.from_key("0x" + "ab" * 32)
OTHER = TempoAccount.from_key("0x" + "cd" * 32)
KEY = _store.channel_key(payee=PAYEE, token=TOKEN, escrow=ESCROW_ADDRESS, chain_id=CHAIN_ID)
URL = "http://api.test/paid"
Calls = dict[str, list[Any]]


def make_challenge(
    *,
    amount: str = "100",
    suggested_deposit: str | None = None,
    chain_id: int | None = CHAIN_ID,
    escrow: str | None = ESCROW_ADDRESS,
    fee_payer: bool | None = None,
    protocol: str = "v2",
    challenge_id: str | None = None,
    **extra_details: Any,
) -> Challenge:
    """A session challenge; extra keywords are added to methodDetails."""
    details: dict[str, Any] = {"sessionProtocol": protocol}
    if escrow is not None:
        details["escrowContract"] = escrow
    if chain_id is not None:
        details["chainId"] = chain_id
    if fee_payer is not None:
        details["feePayer"] = fee_payer
    request: dict[str, Any] = {
        "amount": amount,
        "currency": TOKEN,
        "recipient": PAYEE,
        "unitType": "request",
        "methodDetails": {**details, **extra_details},
    }
    if suggested_deposit is not None:
        request["suggestedDeposit"] = suggested_deposit
    return Challenge(
        id=challenge_id or os.urandom(8).hex(),
        method="tempo",
        intent="session",
        request=request,
        realm="api.test",
        expires=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    )


def descriptor_for(account: TempoAccount = ACCOUNT, salt: str | None = None) -> ChannelDescriptor:
    return ChannelDescriptor(
        payer=account.address,
        payee=PAYEE,
        operator=ZERO_ADDRESS,
        token=TOKEN,
        salt=salt or "0x" + os.urandom(32).hex(),
        authorized_signer=account.address,
        expiring_nonce_hash="0x" + os.urandom(32).hex(),
    )


def entry_for(
    *, cumulative: int = 100, deposit: int = 1000, account: TempoAccount = ACCOUNT
) -> ChannelEntry:
    descriptor = descriptor_for(account)
    return ChannelEntry(
        channel_id=compute_channel_id(descriptor, chain_id=CHAIN_ID),
        cumulative_amount=cumulative,
        deposit=deposit,
        descriptor=descriptor,
        escrow=ESCROW_ADDRESS,
        chain_id=CHAIN_ID,
        opened=True,
    )


def snapshot_wire(
    entry: ChannelEntry,
    *,
    channel_id: str | None = None,
    accepted: int = 100,
    required: int = 100,
    spent: int = 100,
    deposit: int = 1000,
) -> dict[str, Any]:
    return {
        "channelId": channel_id or entry.channel_id,
        "descriptor": entry.descriptor.to_wire(),
        "acceptedCumulative": str(accepted),
        "requiredCumulative": str(required),
        "spent": str(spent),
        "deposit": str(deposit),
    }


def snapshot_challenge(channel_id: str, entry: ChannelEntry | None = None) -> Challenge:
    """A challenge whose snapshot reports channel_id accepted at 100."""
    wire = snapshot_wire(entry or entry_for(), channel_id=channel_id, spent=0)
    return make_challenge(sessionSnapshot=wire)


@pytest.fixture
def fake_chain(monkeypatch: pytest.MonkeyPatch) -> Calls:
    """Replace open/top-up transaction building with deterministic fakes."""
    calls: Calls = {"open": [], "top_up": []}

    async def build_open_transaction(account: TempoAccount, **kwargs: Any) -> Any:
        calls["open"].append(kwargs)
        descriptor = ChannelDescriptor(
            payer=account.address,
            payee=kwargs["payee"],
            operator=kwargs["operator"],
            token=kwargs["token"],
            salt="0x" + os.urandom(32).hex(),
            authorized_signer=kwargs["authorized_signer"],
            expiring_nonce_hash="0x" + os.urandom(32).hex(),
        )
        channel_id = compute_channel_id(
            descriptor, chain_id=kwargs["chain_id"], escrow=kwargs["escrow"]
        )
        return "0x76" + "00" * 8, descriptor, channel_id

    async def build_top_up_transaction(
        account: TempoAccount, descriptor: ChannelDescriptor, additional: int, **kwargs: Any
    ) -> str:
        calls["top_up"].append({"additional": additional, **kwargs})
        return "0x76" + "11" * 8

    monkeypatch.setattr(chain, "build_open_transaction", build_open_transaction)
    monkeypatch.setattr(chain, "build_top_up_transaction", build_top_up_transaction)
    return calls


def on_chain(
    monkeypatch: pytest.MonkeyPatch, *, settled: int = 0, deposit: int = 1000, close: int = 0
) -> list[str]:
    """Fake chain.get_channel_state; returns the channel IDs it was asked for."""
    reads: list[str] = []

    async def get_channel_state(rpc_url: str, channel_id: str, **_: Any) -> chain.ChannelState:
        reads.append(channel_id)
        return chain.ChannelState(settled=settled, deposit=deposit, close_requested_at=close)

    monkeypatch.setattr(chain, "get_channel_state", get_channel_state)
    return reads


def payload_of(authorization: str) -> dict[str, Any]:
    return Credential.from_authorization(authorization).payload


async def pay(
    method: SessionMethod | ClientMethod, challenge: Challenge | None = None, **params: Any
) -> dict[str, Any]:
    """The payload of the method's credential for challenge (a fresh one by default)."""
    challenge = challenge if challenge is not None else make_challenge()
    return payload_of(
        await method.create_credential(CredentialParams(challenge=challenge, **params))
    )


async def _resolve_rpc(requested: int | None) -> tuple[str, int]:
    return "http://rpc.invalid", requested if requested is not None else CHAIN_ID


async def resolved_for(challenge: Challenge, **kwargs: Any) -> _state.ChallengeContext:
    return await _state.resolve_challenge_context(challenge, resolve_rpc=_resolve_rpc, **kwargs)


def sink_for() -> tuple[ChannelSink, list[ChannelEntry]]:
    updates: list[ChannelEntry] = []
    return ChannelSink(store=create_channel_store(), notify_update=updates.append), updates


def receipt_header(channel_id: str, accepted: int = 100, challenge_id: str = "c") -> str:
    receipt = create_session_receipt(
        challenge_id=challenge_id, channel_id=channel_id, accepted_cumulative=accepted, spent=0
    )
    return serialize_session_receipt(receipt)


def required(challenge: Challenge) -> httpx.Response:
    return httpx.Response(
        402, headers={"WWW-Authenticate": challenge.to_www_authenticate("api.test")}
    )


def paid(credential: Credential) -> httpx.Response:
    payload = credential.payload
    header = receipt_header(
        payload["channelId"], int(payload["cumulativeAmount"]), credential.challenge.id
    )
    return httpx.Response(200, headers={"Payment-Receipt": header})


def send_to(
    log: list[httpx.Request], status: int = 204, headers: dict[str, str] | None = None
) -> Callable[[httpx.Request], Awaitable[httpx.Response]]:
    """A management send that records requests and answers status."""

    async def send(request: httpx.Request) -> httpx.Response:
        log.append(request)
        return httpx.Response(status, headers=headers, request=request)

    return send


def top_up_via(log: list[httpx.Request], status: int = 204) -> dict[str, Any]:
    """CredentialParams fields that let the method POST a top-up."""
    return {"request": httpx.Request("GET", URL), "fetch": send_to(log, status)}


async def hang(_: httpx.Request) -> httpx.Response:
    await asyncio.Event().wait()
    raise AssertionError("unreachable")


async def credential_for(challenge: Challenge, _: SessionContext) -> str:
    return f"Payment {challenge.id}"


async def post(send: Any, **kwargs: Any) -> httpx.Response:
    """_session.post_management_credential for a close (by default) to URL."""
    fields: dict[str, Any] = {
        "challenge": make_challenge(),
        "context": SessionContext(action="close"),
        "create_session_credential": credential_for,
        "send": send,
        "url": URL,
        **kwargs,
    }
    return await _session.post_management_credential(**fields)


class SyncKv:
    """A string key-value backend."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.data.get(key)

    def set(self, key: str, value: str) -> None:
        self.data[key] = value

    def delete(self, key: str) -> None:
        self.data.pop(key, None)


class AsyncKv(SyncKv):
    """An async string key-value backend."""

    async def get(self, key: str) -> str | None:  # pyright: ignore[reportIncompatibleMethodOverride]
        return self.data.get(key)

    async def set(self, key: str, value: str) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]
        self.data[key] = value

    async def delete(self, key: str) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]
        self.data.pop(key, None)


@dataclass
class DataclassStore:
    """A mutable dataclass: unhashable (mppx accepts any object as a store)."""

    channels: dict[str, ChannelEntry] = field(default_factory=dict[str, ChannelEntry])

    def get(self, key: str) -> ChannelEntry | None:
        return self.channels.get(key)

    def set(self, entry: ChannelEntry) -> None:
        self.channels[entry_key(entry)] = entry

    def delete(self, key: str) -> None:
        self.channels.pop(key, None)


class SlottedStore:
    """A slotted class without a weakref slot: not weak-referenceable."""

    __slots__ = ("inner",)

    def __init__(self) -> None:
        self.inner = create_channel_store()

    def get(self, key: str) -> ChannelEntry | None:
        return self.inner.get(key)

    def set(self, entry: ChannelEntry) -> None:
        self.inner.set(entry)

    def delete(self, key: str) -> None:
        self.inner.delete(key)


class FakeSessionServer:
    """A minimal mppx-like session server: 402 then accept, 204 for management POSTs."""

    def __init__(self, *, suggested_deposit: str | None = None) -> None:
        self.suggested_deposit = suggested_deposit
        self.requests: list[httpx.Request] = []
        self.spent = 0
        self.accepted = 0
        self.last_challenge: Challenge | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        authorization = request.headers.get("authorization")
        if authorization is None:
            challenge = make_challenge(suggested_deposit=self.suggested_deposit)
            self.last_challenge = challenge
            return required(challenge)
        credential = Credential.from_authorization(authorization)
        payload = credential.payload
        action = payload["action"]
        if action in ("open", "voucher"):
            self.accepted = int(payload["cumulativeAmount"])
            self.spent += 100
        receipt = create_session_receipt(
            challenge_id=credential.challenge.id,
            channel_id=payload["channelId"],
            accepted_cumulative=self.accepted
            if action != "close"
            else int(payload["cumulativeAmount"]),
            spent=self.spent,
            tx_hash="0x" + "ee" * 32 if action in ("topUp", "close") else None,
        )
        headers = {"Payment-Receipt": serialize_session_receipt(receipt)}
        if request.method == "POST":
            return httpx.Response(204, headers=headers)
        return httpx.Response(200, headers=headers, json={"paid": True})


class Server:
    """Answers unpaid requests with one challenge and paid ones from a script."""

    def __init__(self, *paid_responses: Any, suggested_deposit: str | None = "1000") -> None:
        self.challenge = make_challenge(suggested_deposit=suggested_deposit)
        self.script = list(paid_responses)
        self.authorizations: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        authorization = request.headers.get("authorization")
        if authorization is None:
            return required(self.challenge)
        credential = Credential.from_authorization(authorization)
        if request.method == "POST":
            return httpx.Response(204)
        self.authorizations.append(authorization)
        step = self.script.pop(0) if self.script else "accept"
        if step == "accept":
            return paid(credential)
        if isinstance(step, Exception):
            raise step
        if callable(step):
            return cast("httpx.Response", step(credential))
        return cast("httpx.Response", step)

    def hang_when(
        self, predicate: Callable[[httpx.Request], bool]
    ) -> tuple[Callable[[httpx.Request], Awaitable[httpx.Response]], asyncio.Event]:
        """A handler that hangs on matching requests, and the event they set."""
        started = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            if predicate(request):
                started.set()
                await asyncio.Event().wait()
            return self.handler(request)

        return handler, started

    def manager(self, handler: Any = None, **kwargs: Any) -> SessionManager:
        return SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(handler or self.handler), **kwargs
        )

    @property
    def payloads(self) -> list[dict[str, Any]]:
        return [payload_of(value) for value in self.authorizations]


def transport_for(server: Server, method: SessionMethod) -> PaymentTransport:
    return PaymentTransport(
        methods=[method.client_method()], inner=httpx.MockTransport(server.handler)
    )


async def get(transport: PaymentTransport) -> httpx.Response:
    return await transport.handle_async_request(httpx.Request("GET", URL))


def stored(method: SessionMethod) -> ChannelEntry | None:
    channels: dict[str, ChannelEntry] = method.store._channels  # pyright: ignore[reportAttributeAccessIssue,reportUnknownMemberType]
    return next(iter(channels.values()), None)


pytestmark = pytest.mark.usefixtures("fake_chain")


# ── deposit sizing (Runtime.ts) ────────────────────────────────────


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, 100),
        ({"max_deposit": 10_000}, 100),
        ({"suggested_deposit_raw": "5000"}, 5000),
        ({"suggested_deposit_raw": "5000", "max_deposit": 2000}, 2000),
        ({"suggested_deposit_raw": "50"}, 100),
        ({"context_deposit_raw": "700"}, 700),
        ({"context_deposit_raw": "50"}, "below request amount"),
        ({"max_deposit": 99}, "exceeds local maxDeposit"),
    ],
)
def test_opening_deposit(kwargs: dict[str, Any], expected: int | str) -> None:
    if isinstance(expected, str):
        with pytest.raises(ValueError, match=expected):
            _state.resolve_opening_deposit(request_amount=100, **kwargs)
    else:
        assert _state.resolve_opening_deposit(request_amount=100, **kwargs) == expected


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"deposit": 1000, "required_cumulative": 1000}, 0),
        ({}, 100),
        ({"top_up_amount": 500}, 500),
        ({"top_up_amount": 500, "suggested_deposit": 900}, 500),
        ({"suggested_deposit": 900}, 900),
        ({"top_up_amount": 10}, 100),
        ({"top_up_amount": 500, "max_deposit": 300}, 200),
        ({"required_cumulative": 400, "max_deposit": 300}, "exceeds local maxDeposit"),
    ],
)
def test_automatic_top_up(kwargs: dict[str, Any], expected: int | str) -> None:
    kwargs = {"deposit": 100, "required_cumulative": 200, **kwargs}
    if isinstance(expected, str):
        with pytest.raises(ValueError, match=expected):
            _state.resolve_automatic_top_up(**kwargs)
    else:
        assert _state.resolve_automatic_top_up(**kwargs) == expected


# ── challenge policy and resolution ───────────────────────────────


class TestChallengePolicy:
    def test_only_v2_session_challenges_are_handled(self) -> None:
        challenge = make_challenge()
        assert _state.is_tip1034_session_challenge(challenge)
        without_details = {k: v for k, v in challenge.request.items() if k != "methodDetails"}
        for other in (
            make_challenge(protocol="v1"),
            replace(challenge, intent="charge"),
            replace(challenge, method="stripe"),
            replace(challenge, request=without_details),
        ):
            assert not _state.is_tip1034_session_challenge(other)
        method = session(account=ACCOUNT)
        assert method.key == "tempo/session"
        assert method.can_handle_challenge is not None
        assert not method.can_handle_challenge(make_challenge(protocol="v1"))

    async def test_escrow(self) -> None:
        custom = make_challenge(escrow=CUSTOM_ESCROW).request
        with pytest.raises(ValueError, match="does not match client escrow"):
            resolve_escrow(custom)
        assert resolve_escrow(custom, allow_custom_escrow=True) == CUSTOM_ESCROW
        assert resolve_escrow(make_challenge().request) == ESCROW_ADDRESS
        # A pinned escrow takes precedence.
        assert resolve_escrow(custom, CUSTOM_ESCROW) == CUSTOM_ESCROW
        with pytest.raises(ValueError, match="does not match"):
            resolve_escrow(make_challenge().request, CUSTOM_ESCROW, allow_custom_escrow=True)
        assert resolve_escrow(make_challenge(escrow=None).request, CUSTOM_ESCROW) == CUSTOM_ESCROW
        with pytest.raises(ValueError, match="does not match client escrow"):
            await pay(session(account=ACCOUNT), make_challenge(escrow=CUSTOM_ESCROW))

    async def test_chain_allowlist(self) -> None:
        with pytest.raises(ValueError, match="Chain ID not allowed: 4217"):
            await resolved_for(make_challenge(), allowed_chain_ids=(42431,))
        with pytest.raises(ValueError, match="not allowed"):
            await resolved_for(make_challenge(), allowed_chain_ids=())
        resolved = await resolved_for(make_challenge(chain_id=None), allowed_chain_ids=(42431,))
        assert resolved.chain_id == 42431
        resolved = await resolved_for(make_challenge(), allowed_chain_ids=(42431, 4217))
        assert resolved.key == KEY

    async def test_rpc_chain_mismatch_rejected(self) -> None:
        async def other_chain(_: int | None) -> tuple[str, int]:
            return "http://rpc.invalid", 1337

        with pytest.raises(ValueError, match="Chain ID mismatch"):
            await _state.resolve_challenge_context(make_challenge(), resolve_rpc=other_chain)

    @pytest.mark.parametrize(
        ("field", "message"),
        [
            ("recipient", "missing recipient"),
            ("currency", "missing currency"),
            ("amount", "amount"),
        ],
    )
    async def test_missing_request_fields(self, field: str, message: str) -> None:
        challenge = make_challenge()
        request = {k: v for k, v in challenge.request.items() if k != field}
        with pytest.raises(ValueError, match=message):
            await resolved_for(replace(challenge, request=request))

    async def test_optional_fields(self) -> None:
        fee_token, operator = "0x" + "33" * 20, "0x" + "44" * 20
        challenge = make_challenge(fee_payer=False, feeToken=fee_token, operator=operator)
        resolved = await resolved_for(challenge)
        assert (resolved.fee_payer, resolved.fee_token, resolved.operator) == (
            False,
            fee_token,
            operator,
        )
        assert resolved.snapshot is None and resolved.suggested_deposit_raw is None

    def test_read_session_snapshot(self) -> None:
        entry = entry_for()
        assert _state.read_session_snapshot({}) is None
        assert _state.read_session_snapshot({"sessionSnapshot": "x"}) is None
        wire = snapshot_wire(entry, accepted=100, required=200, spent=50, deposit=900)
        snapshot = _state.read_session_snapshot(
            {"sessionSnapshot": {**wire, "acceptedCumulative": 100}}
        )
        assert snapshot == _state.SessionSnapshot(
            channel_id=entry.channel_id,
            descriptor=entry.descriptor,
            accepted_cumulative=100,
            required_cumulative=200,
            spent=50,
            deposit=900,
        )
        for broken in (
            {k: v for k, v in wire.items() if k != "spent"},
            {**wire, "deposit": True},
            {**wire, "deposit": "-1"},
            {**wire, "deposit": 1.5},
            {**wire, "descriptor": {"payer": ACCOUNT.address}},
        ):
            assert _state.read_session_snapshot({"sessionSnapshot": broken}) is None

    def test_read_optional_address(self) -> None:
        assert read_optional_address(PAYEE) == PAYEE
        for value in (1, "0x" + "11" * 19, "0x" + "zz" * 20, "11" * 21):
            assert read_optional_address(value) is None


# ── context amounts, planning and recovery (CredentialState.ts) ───


class TestContextAmounts:
    def test_raw_amount_wins_over_human_amount(self) -> None:
        context = SessionContext(cumulative_amount="1.5", cumulative_amount_raw="7")
        assert _state.parse_optional_context_amount(context, 6, "cumulative_amount") == 7
        context = SessionContext(additional_deposit="0.25")
        assert _state.parse_optional_context_amount(context, 6, "additional_deposit") == 250_000
        assert (
            _state.parse_optional_context_amount(SessionContext(), 6, "additional_deposit") is None
        )

    def test_required_amount_names_the_action(self) -> None:
        with pytest.raises(ValueError, match="additionalDeposit required for topUp action"):
            _state.require_context_amount(SessionContext(), 6, "additional_deposit", "topUp")
        with pytest.raises(ValueError, match="cumulativeAmount required for close action"):
            _state.require_context_amount(SessionContext(), 6, "cumulative_amount", "close")

    def test_recovered_cumulative(self) -> None:
        entry = entry_for()
        snapshot = _state.SessionSnapshot(
            channel_id=entry.channel_id,
            descriptor=entry.descriptor,
            accepted_cumulative=300,
            required_cumulative=350,
            spent=200,
            deposit=1000,
        )
        empty = SessionContext()

        def recovered(context: SessionContext, settled: int, **kwargs: Any) -> int:
            return _state.resolve_recovered_cumulative(
                context=context, decimals=6, request_amount=100, settled=settled, **kwargs
            )

        # A snapshot boundary covers accepted, required, spent + request and settled.
        assert recovered(empty, 0, snapshot=snapshot) == 350
        assert recovered(empty, 500, snapshot=snapshot) == 500
        assert recovered(SessionContext(cumulative_amount_raw="40"), 10) == 140
        assert recovered(empty, 10) == 110


async def _plan(context: SessionContext | None = None, entry: ChannelEntry | None = None) -> str:
    resolved = await resolved_for(make_challenge())
    return _state.plan_credential(
        account=ACCOUNT, entry=entry, resolved=resolved, context=context
    ).type


class TestPlanCredential:
    async def test_automatic_plans(self) -> None:
        assert await _plan() == "open"
        assert await _plan(entry=entry_for()) == "voucher"
        closed = entry_for()
        closed.opened = False
        assert await _plan(entry=closed) == "open"
        # A channel this account cannot sign for is not reused.
        assert await _plan(entry=entry_for(account=OTHER)) == "open"

    async def test_manual_and_recover_require_descriptor(self) -> None:
        with pytest.raises(ValueError, match="descriptor required"):
            await _plan(SessionContext(action="voucher", cumulative_amount_raw="5"))
        manual = SessionContext(action="voucher", descriptor=descriptor_for())
        assert await _plan(manual) == "manual"
        with pytest.raises(ValueError, match="descriptor required to reuse"):
            await _plan(SessionContext(channel_id="0x" + "00" * 32))
        assert await _plan(SessionContext(descriptor=descriptor_for())) == "recover"


class TestReusableChannel:
    async def test_descriptor_must_match_challenge_and_account(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        on_chain(monkeypatch)
        resolved = await resolved_for(make_challenge())
        descriptor = descriptor_for()
        cases: list[tuple[str | None, Any, str]] = [
            ("0x" + "00" * 32, descriptor, "channelId does not match"),
            (None, replace(descriptor, payee="0x" + "99" * 20), "payee does not match"),
            (None, replace(descriptor, token="0x" + "98" * 20), "token does not match"),
            (None, replace(descriptor, payer=OTHER.address), "payer does not match"),
            (None, replace(descriptor, authorized_signer=OTHER.address), "authorizedSigner"),
        ]
        for channel_id, candidate, message in cases:
            with pytest.raises(ValueError, match=message):
                await _state.resolve_reusable_channel(
                    account=ACCOUNT, descriptor=candidate, resolved=resolved, channel_id=channel_id
                )

    async def test_reads_open_state(self, monkeypatch: pytest.MonkeyPatch) -> None:
        reads = on_chain(monkeypatch, settled=40, deposit=900)
        resolved = await resolved_for(make_challenge())
        descriptor = descriptor_for()
        channel_id = compute_channel_id(descriptor, chain_id=CHAIN_ID)
        found, state = await _state.resolve_reusable_channel(
            account=ACCOUNT,
            descriptor=descriptor,
            resolved=resolved,
            channel_id="0x" + channel_id[2:].upper(),
        )
        assert found == channel_id and reads == [channel_id]
        assert (state.settled, state.deposit) == (40, 900)

    @pytest.mark.parametrize(
        ("deposit", "close", "message"),
        [(0, 0, "closed or not found"), (1000, 1_700_000_000, "pending close request")],
    )
    async def test_closed_or_closing_channels_are_not_reused(
        self, monkeypatch: pytest.MonkeyPatch, deposit: int, close: int, message: str
    ) -> None:
        on_chain(monkeypatch, deposit=deposit, close=close)
        resolved = await resolved_for(make_challenge())
        with pytest.raises(ValueError, match=message):
            await _state.resolve_reusable_channel(
                account=ACCOUNT, descriptor=descriptor_for(), resolved=resolved
            )


class TestRecover:
    async def test_recovers_from_server_snapshot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        on_chain(monkeypatch, settled=100, deposit=1000)
        previous = entry_for(cumulative=300)
        wire = snapshot_wire(previous, accepted=300, required=300, spent=250)
        updates: list[ChannelEntry] = []
        method = SessionMethod(account=ACCOUNT, on_channel_update=updates.append)
        voucher = await pay(method, make_challenge(sessionSnapshot=wire))
        assert voucher["action"] == "voucher"
        assert voucher["channelId"] == previous.channel_id
        assert voucher["cumulativeAmount"] == "350"
        (entry,) = updates
        assert (entry.cumulative_amount, entry.deposit, entry.opened) == (350, 1000, True)
        # The recovered channel is cached: the next request signs an incremental voucher.
        assert (await pay(method))["cumulativeAmount"] == "450"

    async def test_snapshot_for_another_payer_opens_new_channel(
        self, monkeypatch: pytest.MonkeyPatch, fake_chain: Calls
    ) -> None:
        on_chain(monkeypatch)
        challenge = make_challenge(sessionSnapshot=snapshot_wire(entry_for(account=OTHER)))
        opened = await pay(SessionMethod(account=ACCOUNT), challenge)
        assert opened["action"] == "open" and len(fake_chain["open"]) == 1

    async def test_recovered_amount_beyond_deposit_or_max_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        on_chain(monkeypatch, settled=950, deposit=1000)
        context = SessionContext(descriptor=descriptor_for())
        method = SessionMethod(account=ACCOUNT)
        with pytest.raises(ValueError, match="exceeds on-chain channel deposit"):
            await method.create_session_credential(make_challenge(), context)
        on_chain(monkeypatch, settled=0, deposit=1000)
        capped = SessionMethod(account=ACCOUNT, max_deposit="0.00005")
        with pytest.raises(ValueError, match="exceeds local maxDeposit"):
            await capped.create_session_credential(make_challenge(), context)

    async def test_recover_keeps_unresolved_top_up_flag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        on_chain(monkeypatch, settled=100, deposit=1000)
        cached = entry_for(cumulative=100)
        cached.uncertain_top_up = True
        sink, updates = sink_for()
        await persist_channel(sink.store, cached)
        plan = _state.CredentialPlan(
            type="recover",
            account=ACCOUNT,
            resolved=await resolved_for(make_challenge()),
            context=SessionContext(descriptor=cached.descriptor),
        )
        payload = await _state.execute_credential_plan(plan, sink)
        assert isinstance(payload, VoucherPayload) and payload.cumulative_amount == "200"
        assert updates[-1].uncertain_top_up


class TestManualActions:
    async def _execute(self, sink: ChannelSink, **context: Any) -> Any:
        resolved = await resolved_for(make_challenge())
        plan = _state.plan_credential(
            account=ACCOUNT, entry=None, resolved=resolved, context=SessionContext(**context)
        )
        return await _state.execute_credential_plan(plan, sink)

    async def test_open_with_caller_transaction(self) -> None:
        descriptor = descriptor_for()
        sink, _ = sink_for()
        with pytest.raises(ValueError, match="transaction required for open"):
            await self._execute(sink, action="open", descriptor=descriptor)
        payload = await self._execute(
            sink,
            action="open",
            descriptor=descriptor,
            transaction="0x76abcd",
            cumulative_amount="0.0001",
        )
        assert (payload.action, payload.transaction, payload.cumulative_amount) == (
            "open",
            "0x76abcd",
            "100",
        )
        assert payload.channel_id == compute_channel_id(descriptor, chain_id=CHAIN_ID)

    async def test_top_up(self, fake_chain: Calls) -> None:
        sink, updates = sink_for()
        payload = await self._execute(
            sink,
            action="topUp",
            descriptor=descriptor_for(),
            transaction="0x76beef",
            additional_deposit_raw="500",
        )
        assert (payload.action, payload.transaction, payload.additional_deposit) == (
            "topUp",
            "0x76beef",
            "500",
        )
        assert updates == []  # a top-up carries no cumulative authorization
        # Without a caller transaction, the method builds one.
        payload = await self._execute(
            sink, action="topUp", descriptor=descriptor_for(), additional_deposit="1"
        )
        assert payload.additional_deposit == "1000000"
        assert fake_chain["top_up"][0]["additional"] == 1_000_000

    async def test_voucher_raises_cached_cumulative(self) -> None:
        cached = entry_for(cumulative=100)
        sink, updates = sink_for()
        await persist_channel(sink.store, cached)
        voucher = {"action": "voucher", "descriptor": cached.descriptor}
        payload = await self._execute(sink, **voucher, cumulative_amount_raw="250")
        assert payload.action == "voucher" and payload.cumulative_amount == "250"
        assert updates[-1].cumulative_amount == 250
        # A lower manual voucher never lowers the cached boundary.
        await self._execute(sink, **voucher, cumulative_amount_raw="150")
        assert updates[-1].cumulative_amount == 250
        # A voucher for another channel leaves the cache alone.
        updates.clear()
        await self._execute(
            sink, action="voucher", descriptor=descriptor_for(), cumulative_amount_raw="5"
        )
        assert updates == []
        cached_now = await _store.store_get(sink.store, KEY)
        assert cached_now is not None and cached_now.cumulative_amount == 250


# ── stores and scope locks (ChannelStore.ts) ──────────────────────


class TestStores:
    @pytest.mark.parametrize("kv_type", [SyncKv, AsyncKv])
    async def test_json_store_round_trips(self, kv_type: type[SyncKv]) -> None:
        kv = kv_type()
        store = create_json_channel_store(kv)
        assert await store.get(KEY) is None
        entry = entry_for(cumulative=2**95, deposit=2**96 - 1)
        entry.uncertain_top_up = True
        await store.set(entry)
        (key,) = kv.data
        assert key == f"chan:{entry_key(entry)}"
        assert json.loads(kv.data[key])["deposit"] == str(2**96 - 1)
        assert _store.serialize_entry(entry)["uncertainTopUp"] is True
        assert await store.get(entry_key(entry)) == entry
        assert _store.deserialize_entry(_store.serialize_entry(entry)) == entry
        await store.delete(entry_key(entry))
        assert kv.data == {}

    async def test_unresolved_top_up_survives_writes_and_deletes(self) -> None:
        store = create_channel_store()
        entry = entry_for()
        entry.uncertain_top_up = True
        store.set(entry)
        stale = entry.copy(uncertain_top_up=False, cumulative_amount=500)
        await persist_channel(store, stale)
        assert stale.uncertain_top_up and store.get(KEY) is stale
        await _store.delete_channel(store, KEY)
        assert store.get(KEY) is stale
        with pytest.raises(UncertainFundingError, match="before replacing the channel"):
            await persist_channel(store, entry_for())
        stale.uncertain_top_up = False
        await _store.delete_channel(store, KEY)
        assert store.get(KEY) is None

    @pytest.mark.parametrize("store_type", [DataclassStore, SlottedStore])
    async def test_session_accepts_any_store_object(self, store_type: type[Any]) -> None:
        store = store_type()
        server = Server()
        transport = transport_for(server, SessionMethod(account=ACCOUNT, channel_store=store))
        for _ in range(2):
            assert (await get(transport)).status_code == 200
        assert [p["action"] for p in server.payloads] == ["open", "voucher"]
        assert store_lock(store, "k") is store_lock(store, "k")

        async def operation() -> str:
            return "ok"

        assert await _store.with_funding_lock(store, "k", operation) == "ok"

    async def test_scope_locks_are_dropped_after_use(self) -> None:
        store = create_channel_store()
        method = SessionMethod(account=ACCOUNT, channel_store=store, max_deposit="0.001")
        transport = transport_for(Server(), method)
        for _ in range(2):
            assert (await get(transport)).status_code == 200
        # A challenge rejected by local policy leaves no lock behind either.
        with pytest.raises(ValueError):
            await pay(method, make_challenge(amount="5000"))
        assert _locks.get(store) == {}

    async def test_scope_lock_is_kept_while_awaited(self) -> None:
        store = create_channel_store()
        lock = store_lock(store, "k")
        await lock.acquire()
        waiter = asyncio.ensure_future(lock.acquire())
        cancelled = asyncio.ensure_future(store_lock(store, "k").acquire())
        await asyncio.sleep(0)
        cancelled.cancel()
        await asyncio.sleep(0)
        lock.release()
        await waiter
        assert store_lock(store, "k") is lock
        lock.release()
        assert _locks.get(store) == {}
        assert store_lock(store, "k") is not lock

    def test_store_map_forgets_collected_stores(self) -> None:
        mapping = _StoreMap()
        store = create_channel_store()
        mapping.set(store, 1)
        assert mapping.get(store) == 1 and mapping.get(create_channel_store()) is None
        replaced = create_channel_store()
        mapping.set(replaced, 2)
        stale: Any = mapping._items[id(replaced)][0]  # pyright: ignore[reportPrivateUsage]
        mapping.set(replaced, 3)
        # A superseded reference's callback leaves the newer entry alone.
        stale.__callback__(stale)
        assert mapping.get(replaced) == 3
        del store
        gc.collect()
        assert len(mapping._items) == 1  # pyright: ignore[reportPrivateUsage]

    async def test_pending_open_store_delegates_reads_and_deletes(self) -> None:
        backing = create_channel_store()
        entry = entry_for()
        backing.set(entry)
        pending: list[ChannelEntry] = []
        view = _PendingOpenStore(backing, pending)
        assert await view.get(entry_key(entry)) is entry
        view.set(entry_for())
        assert len(pending) == 1 and backing.get(entry_key(entry)) is entry
        await view.delete(entry_key(entry))
        assert backing.get(entry_key(entry)) is None


# ── the session client method (Session.ts) ────────────────────────


class TestSessionMethod:
    async def test_open_then_incremental_vouchers(self, fake_chain: Calls) -> None:
        updates: list[ChannelEntry] = []
        method = session(account=ACCOUNT, max_deposit="1", on_channel_update=updates.append)
        opened = await pay(method, make_challenge(suggested_deposit="10000"))
        assert (opened["action"], opened["cumulativeAmount"]) == ("open", "100")
        assert fake_chain["open"][0]["deposit"] == 10_000
        cumulative = [await pay(method) for _ in range(3)]
        assert [p["action"] for p in cumulative] == ["voucher"] * 3
        assert [p["cumulativeAmount"] for p in cumulative] == ["200", "300", "400"]
        assert {p["channelId"] for p in cumulative} == {opened["channelId"]}
        assert updates[-1].cumulative_amount == 400
        last = cumulative[-1]
        signed = SignedVoucher(
            channel_id=last["channelId"],
            cumulative_amount=int(last["cumulativeAmount"]),
            signature=last["signature"],
        )
        assert verify_voucher(ESCROW_ADDRESS, CHAIN_ID, signed, ACCOUNT.address)
        credential = Credential.from_authorization(
            await method.create_credential(CredentialParams(challenge=make_challenge()))
        )
        assert credential.source == f"did:pkh:eip155:{CHAIN_ID}:{ACCOUNT.address}"

    async def test_fee_payer_challenge_builds_sponsored_open(self, fake_chain: Calls) -> None:
        await pay(session(account=ACCOUNT), make_challenge(fee_payer=True))
        assert fake_chain["open"][0]["fee_payer"] is True

    async def test_tops_up_exact_shortfall_before_voucher(self, fake_chain: Calls) -> None:
        method = session(account=ACCOUNT, max_deposit="1")
        await pay(method)
        log: list[httpx.Request] = []
        request = httpx.Request("GET", f"{URL}#frag")
        voucher = await pay(method, request=request, fetch=send_to(log))
        assert voucher["action"] == "voucher" and voucher["cumulativeAmount"] == "200"
        (sent,) = log
        assert sent.method == "POST" and str(sent.url) == URL
        top_up = payload_of(sent.headers["authorization"])
        assert top_up["action"] == "topUp" and top_up["additionalDeposit"] == "100"
        assert fake_chain["top_up"][0]["additional"] == 100

    async def test_uncovered_voucher_fails(self) -> None:
        method = session(account=ACCOUNT)
        await pay(method)
        with pytest.raises(ValueError, match="cannot cover the next voucher"):
            await pay(method)
        with pytest.raises(RuntimeError, match="Top-up POST failed with status 400"):
            await pay(method, **top_up_via([], status=400))

    async def test_unknown_top_up_outcome_blocks_further_funding(self) -> None:
        store = create_channel_store()
        method = session(account=ACCOUNT, channel_store=store)
        await pay(method)

        async def broken(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out", request=request)

        params = {"request": httpx.Request("GET", URL), "fetch": broken}
        with pytest.raises(UncertainFundingError):
            await pay(method, **params)
        (entry,) = store._channels.values()  # pyright: ignore[reportPrivateUsage]
        assert entry.uncertain_top_up
        with pytest.raises(UncertainFundingError, match="reconcile"):
            await pay(method, **params)

    async def test_concurrent_credentials_are_serialized_per_channel(
        self, fake_chain: Calls
    ) -> None:
        method = session(account=ACCOUNT)
        payloads = await asyncio.gather(
            *(pay(method, make_challenge(suggested_deposit="100000")) for _ in range(10))
        )
        assert len(fake_chain["open"]) == 1
        assert sorted(int(p["cumulativeAmount"]) for p in payloads) == list(range(100, 1100, 100))
        assert len({p["channelId"] for p in payloads}) == 1

    async def test_manual_close_marks_channel_closed(self) -> None:
        store = create_channel_store()
        updates: list[ChannelEntry] = []
        method = SessionMethod(
            account=ACCOUNT, channel_store=store, on_channel_update=updates.append
        )
        await method.create_session_credential(make_challenge())
        entry = updates[-1]
        context = SessionContext(
            action="close",
            channel_id=entry.channel_id,
            descriptor=entry.descriptor,
            cumulative_amount_raw="100",
        )
        close = payload_of(await method.create_session_credential(make_challenge(), context))
        assert close["action"] == "close" and close["closeSignature"].startswith("0x")
        assert not updates[-1].opened
        # Neither the automatic open nor the manual close leaves a scope lock behind.
        assert not _store._locks.get(store)  # pyright: ignore[reportPrivateUsage]
        assert store.get(KEY) is None

    def test_configuration(self) -> None:
        assert tempo_client.session is session
        assert tempo_client.session_manager is session_manager
        with pytest.raises(ValueError, match="sequence of chain IDs"):
            SessionMethod(account=ACCOUNT, allowed_chain_ids="4217")  # pyright: ignore[reportArgumentType]
        assert SessionMethod(account=ACCOUNT, allowed_chain_ids=[4217]).allowed_chain_ids == (4217,)

    async def test_rejects_foreign_context_type(self) -> None:
        with pytest.raises(TypeError, match="must be a SessionContext"):
            await pay(SessionMethod(account=ACCOUNT), context={"action": "open"})

    async def test_rpc_url_chain_id_is_read_once(self) -> None:
        calls: list[dict[str, Any]] = []

        def rpc(request: httpx.Request) -> httpx.Response:
            calls.append(json.loads(request.content))
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": hex(CHAIN_ID)})

        async with httpx.AsyncClient(transport=httpx.MockTransport(rpc)) as client:
            method = SessionMethod(account=ACCOUNT, rpc_url="http://rpc.test", http_client=client)
            first = await method.resolve(make_challenge())
            await method.resolve(make_challenge())
        assert first.rpc_url == "http://rpc.test" and first.chain_id == CHAIN_ID
        assert [c["method"] for c in calls] == ["eth_chainId"]

    async def test_open_with_foreign_descriptor_context(self, fake_chain: Calls) -> None:
        """A context descriptor this account cannot sign for opens a fresh channel."""
        store = create_json_channel_store(AsyncKv())
        method = SessionMethod(account=ACCOUNT, channel_store=store)
        context = SessionContext(descriptor=descriptor_for(OTHER))
        opened = payload_of(await method.create_session_credential(make_challenge(), context))
        assert opened["action"] == "open"
        cached = await store.get(KEY)
        assert cached is not None
        await store.set(cached.copy(opened=False))
        reopened = payload_of(await method.create_session_credential(make_challenge(), context))
        assert reopened["action"] == "open" and reopened["channelId"] != opened["channelId"]
        assert len(fake_chain["open"]) == 2

    async def test_foreign_cached_channel_is_not_topped_up(self) -> None:
        store = create_channel_store()
        store.set(entry_for(cumulative=1000, deposit=1000, account=OTHER))
        log: list[httpx.Request] = []
        opened = await pay(SessionMethod(account=ACCOUNT, channel_store=store), **top_up_via(log))
        assert opened["action"] == "open" and log == []

    async def test_snapshot_for_other_channel_is_ignored(self) -> None:
        method = SessionMethod(account=ACCOUNT)
        await pay(method, make_challenge(suggested_deposit="1000"))
        wire = snapshot_wire(entry_for(), required=5000, deposit=9000)
        voucher = await pay(method, make_challenge(sessionSnapshot=wire))
        assert voucher["action"] == "voucher" and voucher["cumulativeAmount"] == "200"

    async def test_snapshot_deposit_is_adopted_without_top_up(self, fake_chain: Calls) -> None:
        updates: list[ChannelEntry] = []
        method = SessionMethod(account=ACCOUNT, on_channel_update=updates.append)
        await pay(method)
        channel = updates[-1]

        def challenge(required: int) -> Challenge:
            wire = snapshot_wire(channel, required=required, deposit=5000)
            return make_challenge(sessionSnapshot=wire)

        # Without a request to top up through, the larger server deposit still covers it.
        assert (await pay(method, challenge(200)))["cumulativeAmount"] == "200"
        log: list[httpx.Request] = []
        await pay(method, challenge(300), **top_up_via(log))
        assert log == []  # no top-up POST: the server deposit covers the voucher
        assert updates[-1].deposit == 5000
        assert fake_chain["top_up"] == []

    async def test_top_up_not_needed_returns_without_post(self) -> None:
        store = create_channel_store()
        channel = entry_for(cumulative=100, deposit=1000)
        store.set(channel)
        log: list[httpx.Request] = []
        receipt = await SessionMethod(
            account=ACCOUNT, channel_store=store
        ).top_up_channel_if_needed(
            challenge=make_challenge(),
            channel=channel,
            deposit=500,
            required_cumulative=200,
            url=URL,
            send=send_to(log),
        )
        assert receipt is None and log == []

    async def test_top_up_for_uncached_channel_uses_given_entry(self) -> None:
        store = create_channel_store()
        store.set(entry_for())  # a different channel in the same scope
        channel = entry_for(cumulative=100, deposit=100)
        updates: list[ChannelEntry] = []
        method = SessionMethod(
            account=ACCOUNT, channel_store=store, on_channel_update=updates.append
        )
        log: list[httpx.Request] = []
        await method.top_up_channel_if_needed(
            challenge=make_challenge(),
            channel=channel,
            deposit=100,
            required_cumulative=300,
            url=URL,
            send=send_to(log),
        )
        (sent,) = log
        top_up = payload_of(sent.headers["authorization"])
        assert top_up["channelId"] == channel.channel_id and top_up["additionalDeposit"] == "200"
        assert updates[-1].channel_id == channel.channel_id and updates[-1].deposit == 300

    async def test_post_top_up(self) -> None:
        channel = entry_for()
        method = SessionMethod(account=ACCOUNT)
        headers = {"Payment-Receipt": receipt_header(channel.channel_id)}

        async def post_top_up(channel: ChannelEntry, send: Any) -> Any:
            return await method.post_top_up(
                challenge=make_challenge(),
                channel=channel,
                additional_deposit=10,
                url=URL,
                send=send,
            )

        receipt = await post_top_up(channel, send_to([], headers=headers))
        assert receipt is not None and receipt.channel_id == channel.channel_id
        unresolved = entry_for()
        unresolved.uncertain_top_up = True
        with pytest.raises(UncertainFundingError, match="before another top-up"):
            await post_top_up(unresolved, send_to([]))
        # A cancelled POST marks the stored channel's funding uncertain.
        method.store.set(channel)
        task = asyncio.create_task(post_top_up(channel, hang))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        entry = await _store.store_get(method.store, entry_key(channel))
        assert entry is not None and entry.uncertain_top_up


# ── management POSTs ──────────────────────────────────────────────


class TestManagementHelpers:
    def test_headers_for_custom_credential_header(self) -> None:
        custom = replace(make_challenge(), header="Payment-Authorization")
        headers = _session.management_headers(custom, "Payment abc", "Bearer token")
        assert headers["payment-authorization"] == "Payment abc"
        assert headers["authorization"] == "Bearer token"
        # A Payment credential in Authorization is never forwarded alongside a new one.
        assert "authorization" not in _session.management_headers(
            custom, "Payment abc", "Payment old"
        )
        headers = _session.management_headers(make_challenge(), "Payment abc", "Bearer token")
        assert headers["authorization"] == "Payment abc"

    def test_session_challenges_filters_and_skips_malformed(self) -> None:
        session_challenge = make_challenge()
        response = httpx.Response(
            402,
            headers=[
                ("WWW-Authenticate", 'Payment id="broken"'),
                ("WWW-Authenticate", make_challenge(protocol="v1").to_www_authenticate("x")),
                ("WWW-Authenticate", session_challenge.to_www_authenticate("api.test")),
                ("WWW-Authenticate", 'Bearer realm="api.test"'),
            ],
        )
        assert [c.id for c in _session.session_challenges(response)] == [session_challenge.id]

    def test_read_receipt(self) -> None:
        assert _session.read_receipt(httpx.Response(200)) is None
        assert (
            _session.read_receipt(httpx.Response(200, headers={"Payment-Receipt": "%%%"})) is None
        )
        header = receipt_header("0x" + "aa" * 32)
        receipt = _session.read_receipt(httpx.Response(200, headers={"Payment-Receipt": header}))
        assert receipt is not None and receipt.channel_id == "0x" + "aa" * 32

    async def test_post_retries_once_on_fresh_challenge(self) -> None:
        first, fresh = make_challenge(), make_challenge()
        seen: list[Challenge] = []
        sent: list[httpx.Request] = []

        async def send(request: httpx.Request) -> httpx.Response:
            sent.append(request)
            return required(fresh) if len(sent) == 1 else httpx.Response(204)

        response = await post(
            send, challenge=first, url=f"{URL}?x=1#frag", on_challenge=seen.append
        )
        assert response.status_code == 204
        assert [r.headers["authorization"] for r in sent] == [
            f"Payment {first.id}",
            f"Payment {fresh.id}",
        ]
        assert [c.id for c in seen] == [fresh.id]
        assert str(sent[0].url) == f"{URL}?x=1"
        # The retry needs no observer.
        sent.clear()
        response = await post(send, challenge=first)
        assert response.status_code == 204 and len(sent) == 2

    async def test_post_failures(self) -> None:
        # A 402 without a session challenge is returned; transport errors propagate.
        assert (await post(send_to([], status=402))).status_code == 402

        async def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        with pytest.raises(httpx.ConnectError):
            await post(refuse)

    @pytest.mark.parametrize("action", ["topUp", "close"])
    async def test_only_cancelled_top_up_requests_are_uncertain(self, action: Any) -> None:
        called: list[bool] = []

        async def mark() -> None:
            called.append(True)

        context = SessionContext(action=action)
        task = asyncio.create_task(post(hang, context=context, on_cancelled_top_up=mark))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert called == ([True] if action == "topUp" else [])


# ── plain transport: deferred opens (mppx Session.ts, Fetch.ts) ────


class TestDeferredOpen:
    async def test_rejected_open_is_not_stored(self) -> None:
        # A replacement challenge rejects the open: the next credential opens again
        # instead of signing a voucher for a channel the server never opened.
        server = Server(lambda _: required(make_challenge()))
        method = SessionMethod(account=ACCOUNT)
        assert (await get(transport_for(server, method))).status_code == 200
        first, second = server.payloads
        assert (first["action"], second["action"]) == ("open", "open")
        entry = stored(method)
        assert entry is not None and entry.channel_id == second["channelId"]
        assert entry.cumulative_amount == 100

    @pytest.mark.parametrize("status", [500, 403, 307, None])
    async def test_unaccepted_open_is_discarded(self, status: int | None) -> None:
        # None: the send fails, so the outcome is unknown.
        location = {"Location": "http://api.test/other"}
        response = httpx.Response(status, headers=location) if status else None
        server = Server(response or httpx.ConnectError("reset"))
        method = SessionMethod(account=ACCOUNT)
        transport = transport_for(server, method)
        if status is None:
            with pytest.raises(PaymentOutcomeUnknownError):
                await get(transport)
        else:
            assert (await get(transport)).status_code == status
        assert stored(method) is None
        # The scope lock was released: the next request opens a channel.
        assert (await get(transport)).status_code == 200
        assert [p["action"] for p in server.payloads] == ["open", "open"]
        assert stored(method) is not None

    async def test_identical_challenge_resends_the_credential(self, fake_chain: Calls) -> None:
        server = Server()
        server.script = [lambda _: required(server.challenge)] * 2
        method = SessionMethod(account=ACCOUNT)
        transport = transport_for(server, method)
        assert (await get(transport)).status_code == 200
        assert len(server.authorizations) == 3 and len(set(server.authorizations)) == 1
        assert len(fake_chain["open"]) == 1
        # Vouchers too: one increment per request, however often the challenge repeats.
        server.script = [lambda _: required(server.challenge)]
        assert (await get(transport)).status_code == 200
        assert server.authorizations[3] == server.authorizations[4]
        entry = stored(method)
        assert entry is not None and entry.cumulative_amount == 200

    async def test_repeated_challenges_exhaust_and_discard(self) -> None:
        server = Server()
        server.script = [lambda _: required(server.challenge)] * 3
        method = SessionMethod(account=ACCOUNT)
        assert (await get(transport_for(server, method))).status_code == 402
        assert len(set(server.authorizations)) == 1 and stored(method) is None

    async def test_snapshot_acknowledges_open(self) -> None:
        server = Server(lambda c: required(snapshot_challenge(c.payload["channelId"])))
        assert (await get(transport_for(server, SessionMethod(account=ACCOUNT)))).status_code == 200
        first, second = server.payloads
        assert (first["action"], second["action"]) == ("open", "voucher")
        assert first["channelId"] == second["channelId"]
        assert second["cumulativeAmount"] == "200"

    async def test_accepted_open_already_stored_is_kept(self) -> None:
        method = SessionMethod(account=ACCOUNT)
        attempt = PaymentAttempt()
        opened = await pay(method, attempt=attempt)
        assert stored(method) is None and attempt.settle is not None
        updates: list[ChannelEntry] = []
        method.on_channel_update = updates.append
        current = replace(entry_for(cumulative=500), channel_id=opened["channelId"])
        method.store.set(current)
        # The same channel is already stored (and further along): nothing is replaced.
        assert await attempt.settle(AttemptOutcome(status="accepted"))
        assert stored(method) is current and updates == []

    def test_acknowledgement_requires_matching_challenge_and_amount(self) -> None:
        entry = entry_for()
        challenge = make_challenge()

        def receipt(challenge_id: str, accepted: int) -> httpx.Response:
            header = receipt_header(entry.channel_id, accepted, challenge_id)
            return httpx.Response(402, headers={"Payment-Receipt": header})

        def acknowledges(**kwargs: Any) -> bool:
            return _acknowledges_open(AttemptOutcome(status="rejected", **kwargs), challenge, entry)

        assert acknowledges(response=receipt(challenge.id, 100))
        assert not acknowledges(response=receipt("other", 100))
        assert not acknowledges(response=receipt(challenge.id, 99))
        assert not acknowledges(response="not http")
        assert not acknowledges(challenges=(make_challenge(protocol="v1"), make_challenge()))
        assert acknowledges(challenges=(snapshot_challenge(entry.channel_id),))
        assert not _matches_open(entry, entry.channel_id, "not a number")

    async def test_cancelled_credential_event_releases_the_scope(self) -> None:
        # Cancelled after signing an open but before sending it: the open is dropped
        # and the scope lock released, so later requests do not hang (mppx Fetch).
        server = Server()
        method = SessionMethod(account=ACCOUNT)
        transport = transport_for(server, method)
        cancel = [True]

        async def on_created(_: Any) -> None:
            if cancel.pop() if cancel else False:
                raise asyncio.CancelledError

        transport.on(CREDENTIAL_CREATED, on_created)
        with pytest.raises(asyncio.CancelledError):
            await get(transport)
        assert stored(method) is None and server.authorizations == []
        assert (await asyncio.wait_for(get(transport), 5)).status_code == 200
        assert [p["action"] for p in server.payloads] == ["open"]

    async def test_malformed_receipt_releases_the_scope(self) -> None:
        # A receipt nested past the recursion limit is ignored like any malformed one.
        nested = base64.urlsafe_b64encode(b"[" * 100_000 + b"]" * 100_000).rstrip(b"=")
        server = Server(httpx.Response(403, headers={"Payment-Receipt": nested.decode()}))
        method = SessionMethod(account=ACCOUNT)
        transport = transport_for(server, method)
        assert (await get(transport)).status_code == 403
        assert stored(method) is None
        assert (await asyncio.wait_for(get(transport), 5)).status_code == 200

    async def test_failed_acknowledgement_check_releases_the_scope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        method = SessionMethod(account=ACCOUNT)
        attempt = PaymentAttempt()
        await pay(method, attempt=attempt)
        assert attempt.settle is not None

        def fail(*_: Any) -> bool:
            raise RuntimeError("boom")

        session_module = sys.modules["mpp.methods.tempo.session.client._session"]
        monkeypatch.setattr(session_module, "_acknowledges_open", fail)
        with pytest.raises(RuntimeError, match="boom"):
            await attempt.settle(AttemptOutcome(status="rejected"))
        assert not store_lock(method.store, f"channel:{KEY}").locked()


class TestTransportCompatibility:
    async def test_runtime_with_old_create_credential_signature(self) -> None:
        class OldRuntime(PaymentRuntime):
            async def create_credential(  # pyright: ignore[reportIncompatibleMethodOverride]
                self,
                challenge: Challenge,
                method: ClientMethod,
                *,
                event_payload: dict[str, Any] | None = None,
            ) -> Credential:
                return await super().create_credential(
                    challenge, method, event_payload=event_payload
                )

        method = SessionMethod(account=ACCOUNT)
        transport = PaymentTransport(
            runtime=OldRuntime([method.client_method()]),
            inner=httpx.MockTransport(Server().handler),
        )
        assert (await get(transport)).status_code == 200
        # Without an attempt the open is stored as soon as it is signed.
        assert stored(method) is not None

    def test_accepted_keywords(self) -> None:
        names = ("request", "fetch", "attempt")
        assert _accepted_keywords(object(), names) == frozenset(names)

        def positional(challenge: Any, method: Any, request: Any = None) -> None: ...

        assert _accepted_keywords(positional, names) == frozenset({"request"})

        def keywords(challenge: Any, method: Any, **kwargs: Any) -> None: ...

        assert _accepted_keywords(keywords, names) == frozenset(names)

    def test_response_challenges(self) -> None:
        assert _response_challenges(httpx.Response(200)) == ()
        challenge = make_challenge()
        response = httpx.Response(
            402,
            headers=[
                ("WWW-Authenticate", "Payment broken"),
                ("WWW-Authenticate", challenge.to_www_authenticate("api.test")),
            ],
        )
        assert [c.id for c in _response_challenges(response)] == [challenge.id]


# ── HTTP: Mpp and the session manager (SessionManager.ts) ─────────


class TestHttp:
    async def test_mpp_pays_session_challenges_with_top_ups(self) -> None:
        server = FakeSessionServer()
        async with Mpp(methods=[session(account=ACCOUNT, max_deposit="1")]) as mpp:
            mpp.payment_transport._inner = httpx.MockTransport(server.handler)  # pyright: ignore[reportPrivateUsage]
            for _ in range(3):
                assert (await mpp.fetch(URL)).status_code == 200
        actions = [
            (r.method, payload_of(r.headers["authorization"])["action"])
            for r in server.requests
            if "authorization" in r.headers
        ]
        assert actions == [
            ("GET", "open"),
            ("POST", "topUp"),
            ("GET", "voucher"),
            ("POST", "topUp"),
            ("GET", "voucher"),
        ]
        assert all(
            r.headers["accept-payment"] == "tempo/session"
            for r in server.requests
            if r.method == "GET" and "authorization" not in r.headers
        )

    async def test_manager_fetch_top_up_close(self) -> None:
        server = FakeSessionServer(suggested_deposit="1000")
        async with SessionManager(
            account=ACCOUNT, max_deposit="1", transport=httpx.MockTransport(server.handler)
        ) as manager:
            with pytest.raises(ValueError, match="no open channel"):
                await manager.top_up("1")
            first = await manager.fetch(URL)
            assert first.status_code == 200 and first.json() == {"paid": True}
            assert first.receipt is not None and first.receipt.accepted_cumulative == "100"
            second = await manager.fetch(URL)
            assert second.cumulative == 200 == manager.cumulative
            assert (manager.deposit, manager.spent) == (1000, 200)
            hinted = [r for r in server.requests if r.method == "GET"][2]
            assert hinted.headers["payment-session"] == manager.channel_id

            assert await manager.top_up("0.0005") is not None
            assert manager.deposit == 1500
            sent = payload_of(server.requests[-1].headers["authorization"])
            assert sent["additionalDeposit"] == "500"

            channel_id = manager.channel_id
            closed = await manager.close()
            assert closed is not None and closed.channel_id == channel_id
            close_payload = payload_of(server.requests[-1].headers["authorization"])
            assert close_payload["action"] == "close" and close_payload["cumulativeAmount"] == "200"
            assert not manager.opened

    async def test_manager_rejects_concurrent_fetch(self) -> None:
        gate = asyncio.Event()
        server = FakeSessionServer()

        async def handler(request: httpx.Request) -> httpx.Response:
            await gate.wait()
            return server.handler(request)

        manager = session_manager(account=ACCOUNT, transport=httpx.MockTransport(handler))
        first = asyncio.create_task(manager.fetch(URL))
        await asyncio.sleep(0)
        with pytest.raises(RuntimeError, match="already in flight"):
            await manager.fetch(URL)
        gate.set()
        assert (await first).status_code == 200
        await manager.aclose()


class TestManagerRetryChallenges:
    """Replacement challenges (mppx SessionManager onChallenge)."""

    async def test_snapshot_commits_open(self) -> None:
        server = Server(
            lambda c: required(snapshot_challenge(c.payload["channelId"])), httpx.Response(500)
        )
        async with server.manager() as manager:
            # The committed open survives the voucher's failure; only the voucher is undone.
            assert (await manager.fetch(URL)).status_code == 500
            first, second = server.payloads
            assert (first["action"], second["action"]) == ("open", "voucher")
            assert manager.channel_id == first["channelId"] and manager.cumulative == 100

    async def test_snapshot_for_another_channel_rolls_back_open(self) -> None:
        # Another payer's channel: the snapshot neither commits nor recovers it.
        other = entry_for(account=OTHER)
        server = Server(lambda _: required(snapshot_challenge(other.channel_id, other)))
        async with server.manager() as manager:
            assert (await manager.fetch(URL)).status_code == 200
            assert [p["action"] for p in server.payloads] == ["open", "open"]

    @pytest.mark.parametrize(
        ("replacement", "amounts", "cumulative"),
        [
            # A repeated challenge ID with a new amount restores the voucher boundary.
            ("changed", ["200", "150"], 150),
            # The identical challenge resends the voucher.
            ("identical", ["200", "200"], 200),
            # As in mppx, a challenge with a new ID keeps the retried voucher.
            ("fresh", ["200", "300"], 300),
        ],
    )
    async def test_voucher_retry(
        self,
        replacement: str,
        amounts: list[str],
        cumulative: int,
    ) -> None:
        server = Server()
        challenges = {
            "changed": replace(
                server.challenge, request={**server.challenge.request, "amount": "50"}
            ),
            "identical": server.challenge,
            "fresh": make_challenge(),
        }
        async with server.manager() as manager:
            await manager.fetch(URL)
            server.script = [lambda _: required(challenges[replacement])]
            assert (await manager.fetch(URL)).status_code == 200
            assert [p["cumulativeAmount"] for p in server.payloads[1:]] == amounts
            if replacement == "identical":
                assert server.authorizations[1] == server.authorizations[2]
            assert manager.cumulative == cumulative

    async def test_identical_challenge_event_changes_nothing(self) -> None:
        async with Server().manager() as manager:
            challenge = make_challenge()
            manager._use = _FetchUse(  # pyright: ignore[reportPrivateUsage]
                previous=None, previous_spent=0, challenges_received=1
            )
            manager._last_challenge = challenge  # pyright: ignore[reportPrivateUsage]
            await manager._on_challenge_received(  # pyright: ignore[reportPrivateUsage]
                {"challenge": replace(challenge)}
            )
            assert manager.last_challenge is challenge
            manager._use = None  # pyright: ignore[reportPrivateUsage]
            await manager._rollback()  # pyright: ignore[reportPrivateUsage]


class TestManagerCancellation:
    """Cancelled top-ups leave funding uncertain (mppx abort → UncertainFundingError)."""

    @pytest.mark.parametrize("trigger", ["manual", "automatic"])
    async def test_cancelled_top_up_blocks_funding(self, trigger: str) -> None:
        # Without a suggested deposit (100), the next voucher needs an automatic top-up.
        server = Server(suggested_deposit="1000" if trigger == "manual" else None)
        handler, hanging = server.hang_when(lambda request: request.method == "POST")
        async with server.manager(handler) as manager:
            await manager.fetch(URL)
            task = asyncio.create_task(
                manager.top_up(100) if trigger == "manual" else manager.fetch(URL)
            )
            await hanging.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(UncertainFundingError, match="cancelled"):
                await manager.fetch(URL)
            with pytest.raises(UncertainFundingError, match="cancelled"):
                await manager.top_up(100)

    async def test_cancelled_fetch_without_funding(self) -> None:
        server = Server()
        handler, started = server.hang_when(lambda request: bool(request.headers.get("x-hang")))
        async with server.manager(handler) as manager:
            for opened in (False, True):
                if opened:
                    await manager.fetch(URL)
                started.clear()
                task = asyncio.create_task(manager.fetch(URL, headers={"x-hang": "1"}))
                await started.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert (await manager.fetch(URL)).status_code == 200
