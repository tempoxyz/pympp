"""Unit tests for the TIP-1034 session client internals (mppx CredentialState, ChannelOps,
ChannelStore and Session tests): snapshot parsing, recovery from a descriptor or server
snapshot, manual actions, store coordination and management POSTs. Chain access is faked."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import httpx
import pytest

from mpp import Challenge
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo.session import chain
from mpp.methods.tempo.session.channel import compute_channel_id
from mpp.methods.tempo.session.client import (
    ChannelEntry,
    SessionContext,
    SessionMethod,
    UncertainFundingError,
    channel_key,
    create_channel_store,
    create_json_channel_store,
    serialize_entry,
)
from mpp.methods.tempo.session.client.ops import read_optional_address
from mpp.methods.tempo.session.client.session import (
    management_headers,
    post_management_credential,
    read_receipt,
    session_challenges,
)
from mpp.methods.tempo.session.client.state import (
    ChannelSink,
    CredentialPlan,
    SessionSnapshot,
    execute_credential_plan,
    is_tip1034_session_challenge,
    parse_optional_context_amount,
    plan_credential,
    read_session_snapshot,
    require_context_amount,
    resolve_recovered_cumulative,
    resolve_reusable_channel,
)
from mpp.methods.tempo.session.client.store import (
    delete_channel,
    entry_key,
    persist_channel,
    register_funding_store,
    store_get,
    store_lock,
    with_funding_lock,
)
from mpp.methods.tempo.session.protocol import (
    ESCROW_ADDRESS,
    VoucherPayload,
    create_session_receipt,
    serialize_session_receipt,
)
from mpp.runtime import CredentialParams
from tests import test_session_client as client_tests
from tests.test_session_client import (
    ACCOUNT,
    CHAIN_ID,
    PAYEE,
    TOKEN,
    descriptor_for,
    entry_for,
    make_challenge,
    payload_of,
    resolved_for,
)

fake_chain = client_tests.fake_chain
OTHER = TempoAccount.from_key("0x" + "cd" * 32)
KEY = channel_key(payee=PAYEE, token=TOKEN, escrow=ESCROW_ADDRESS, chain_id=CHAIN_ID)


def with_details(challenge: Challenge, **details: Any) -> Challenge:
    """The challenge with extra methodDetails fields."""
    request = dict(challenge.request)
    request["methodDetails"] = {**request["methodDetails"], **details}
    return replace(challenge, request=request)


def snapshot_wire(
    entry: ChannelEntry,
    *,
    accepted: int = 100,
    required: int = 100,
    spent: int = 100,
    deposit: int = 1000,
) -> dict[str, Any]:
    return {
        "channelId": entry.channel_id,
        "descriptor": entry.descriptor.to_wire(),
        "acceptedCumulative": str(accepted),
        "requiredCumulative": str(required),
        "spent": str(spent),
        "deposit": str(deposit),
    }


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


def sink_for() -> tuple[ChannelSink, list[ChannelEntry]]:
    updates: list[ChannelEntry] = []
    return ChannelSink(store=create_channel_store(), notify_update=updates.append), updates


class AsyncKv:
    """An async string key-value backend."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.data.get(key)

    async def set(self, key: str, value: str) -> None:
        self.data[key] = value

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)


# ── ops ───────────────────────────────────────────────────────────


def test_read_optional_address() -> None:
    assert read_optional_address(PAYEE) == PAYEE
    assert read_optional_address(1) is None
    assert read_optional_address("0x" + "11" * 19) is None
    assert read_optional_address("0x" + "zz" * 20) is None
    assert read_optional_address("11" * 21) is None


# ── challenge resolution ──────────────────────────────────────────


class TestChallengeResolution:
    def test_non_session_challenges_are_ignored(self) -> None:
        assert not is_tip1034_session_challenge(replace(make_challenge(), intent="charge"))
        assert not is_tip1034_session_challenge(replace(make_challenge(), method="stripe"))
        challenge = make_challenge()
        request = dict(challenge.request)
        request.pop("methodDetails")
        assert not is_tip1034_session_challenge(replace(challenge, request=request))

    def test_read_session_snapshot(self) -> None:
        entry = entry_for()
        assert read_session_snapshot({}) is None
        assert read_session_snapshot({"sessionSnapshot": "x"}) is None
        wire = snapshot_wire(entry, accepted=100, required=200, spent=50, deposit=900)
        snapshot = read_session_snapshot({"sessionSnapshot": {**wire, "acceptedCumulative": 100}})
        assert snapshot == SessionSnapshot(
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
            assert read_session_snapshot({"sessionSnapshot": broken}) is None

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
        request = dict(challenge.request)
        request.pop(field)
        with pytest.raises(ValueError, match=message):
            await resolved_for(replace(challenge, request=request))

    async def test_optional_fields(self) -> None:
        fee_token = "0x" + "33" * 20
        operator = "0x" + "44" * 20
        challenge = with_details(
            make_challenge(fee_payer=False), feeToken=fee_token, operator=operator
        )
        resolved = await resolved_for(challenge)
        assert resolved.fee_payer is False
        assert resolved.fee_token == fee_token
        assert resolved.operator == operator
        assert resolved.snapshot is None
        assert resolved.suggested_deposit_raw is None


# ── context amounts and recovery ──────────────────────────────────


class TestContextAmounts:
    def test_raw_amount_wins_over_human_amount(self) -> None:
        context = SessionContext(cumulative_amount="1.5", cumulative_amount_raw="7")
        assert parse_optional_context_amount(context, 6, "cumulative_amount") == 7
        context = SessionContext(additional_deposit="0.25")
        assert parse_optional_context_amount(context, 6, "additional_deposit") == 250_000
        assert parse_optional_context_amount(SessionContext(), 6, "additional_deposit") is None

    def test_required_amount_names_the_action(self) -> None:
        with pytest.raises(ValueError, match="additionalDeposit required for topUp action"):
            require_context_amount(SessionContext(), 6, "additional_deposit", "topUp")
        with pytest.raises(ValueError, match="cumulativeAmount required for close action"):
            require_context_amount(SessionContext(), 6, "cumulative_amount", "close")

    def test_recovered_cumulative(self) -> None:
        entry = entry_for()
        snapshot = SessionSnapshot(
            channel_id=entry.channel_id,
            descriptor=entry.descriptor,
            accepted_cumulative=300,
            required_cumulative=350,
            spent=200,
            deposit=1000,
        )
        empty = SessionContext()

        def recovered(context: SessionContext, settled: int, **kwargs: Any) -> int:
            return resolve_recovered_cumulative(
                context=context, decimals=6, request_amount=100, settled=settled, **kwargs
            )

        # A snapshot boundary covers accepted, required, spent + request and settled.
        assert recovered(empty, 0, snapshot=snapshot) == 350
        assert recovered(empty, 500, snapshot=snapshot) == 500
        assert recovered(SessionContext(cumulative_amount_raw="40"), 10) == 140
        assert recovered(empty, 10) == 110


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
                await resolve_reusable_channel(
                    account=ACCOUNT, descriptor=candidate, resolved=resolved, channel_id=channel_id
                )

    async def test_reads_open_state(self, monkeypatch: pytest.MonkeyPatch) -> None:
        reads = on_chain(monkeypatch, settled=40, deposit=900)
        resolved = await resolved_for(make_challenge())
        descriptor = descriptor_for()
        channel_id = compute_channel_id(descriptor, chain_id=CHAIN_ID)
        found, state = await resolve_reusable_channel(
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
            await resolve_reusable_channel(
                account=ACCOUNT, descriptor=descriptor_for(), resolved=resolved
            )


# ── planning and execution ────────────────────────────────────────


class TestRecover:
    async def test_recovers_from_server_snapshot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        on_chain(monkeypatch, settled=100, deposit=1000)
        previous = entry_for(cumulative=300)
        challenge = with_details(
            make_challenge(),
            sessionSnapshot=snapshot_wire(previous, accepted=300, required=300, spent=250),
        )
        updates: list[ChannelEntry] = []
        method = SessionMethod(account=ACCOUNT, on_channel_update=updates.append)
        voucher = payload_of(await method.create_credential(CredentialParams(challenge=challenge)))
        assert voucher["action"] == "voucher"
        assert voucher["channelId"] == previous.channel_id
        assert voucher["cumulativeAmount"] == "350"
        (entry,) = updates
        assert (entry.cumulative_amount, entry.deposit, entry.opened) == (350, 1000, True)
        # The recovered channel is cached: the next request signs an incremental voucher.
        follow_up = payload_of(
            await method.create_credential(CredentialParams(challenge=make_challenge()))
        )
        assert follow_up["cumulativeAmount"] == "450"

    async def test_snapshot_for_another_payer_opens_new_channel(
        self, monkeypatch: pytest.MonkeyPatch, fake_chain: dict[str, list[Any]]
    ) -> None:
        on_chain(monkeypatch)
        challenge = with_details(
            make_challenge(), sessionSnapshot=snapshot_wire(entry_for(account=OTHER))
        )
        method = SessionMethod(account=ACCOUNT)
        opened = payload_of(await method.create_credential(CredentialParams(challenge=challenge)))
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
        resolved = await resolved_for(make_challenge())
        plan = CredentialPlan(
            type="recover",
            account=ACCOUNT,
            resolved=resolved,
            context=SessionContext(descriptor=cached.descriptor),
        )
        payload = await execute_credential_plan(plan, sink)
        assert isinstance(payload, VoucherPayload) and payload.cumulative_amount == "200"
        assert updates[-1].uncertain_top_up


class TestManualActions:
    async def _plan(self, context: SessionContext) -> CredentialPlan:
        resolved = await resolved_for(make_challenge())
        return plan_credential(account=ACCOUNT, entry=None, resolved=resolved, context=context)

    async def test_open_with_caller_transaction(self) -> None:
        descriptor = descriptor_for()
        sink, _ = sink_for()
        with pytest.raises(ValueError, match="transaction required for open"):
            await execute_credential_plan(
                await self._plan(SessionContext(action="open", descriptor=descriptor)), sink
            )
        plan = await self._plan(
            SessionContext(
                action="open",
                descriptor=descriptor,
                transaction="0x76abcd",
                cumulative_amount="0.0001",
            )
        )
        payload = await execute_credential_plan(plan, sink)
        assert payload.action == "open"
        assert payload.transaction == "0x76abcd"
        assert payload.cumulative_amount == "100"
        assert payload.channel_id == compute_channel_id(descriptor, chain_id=CHAIN_ID)

    async def test_top_up_with_caller_transaction(self) -> None:
        sink, updates = sink_for()
        plan = await self._plan(
            SessionContext(
                action="topUp",
                descriptor=descriptor_for(),
                transaction="0x76beef",
                additional_deposit_raw="500",
            )
        )
        payload = await execute_credential_plan(plan, sink)
        assert payload.action == "topUp"
        assert payload.transaction == "0x76beef" and payload.additional_deposit == "500"
        assert updates == []  # a top-up carries no cumulative authorization

    async def test_top_up_builds_transaction(self, fake_chain: dict[str, list[Any]]) -> None:
        sink, _ = sink_for()
        plan = await self._plan(
            SessionContext(action="topUp", descriptor=descriptor_for(), additional_deposit="1")
        )
        payload = await execute_credential_plan(plan, sink)
        assert payload.action == "topUp" and payload.additional_deposit == "1000000"
        assert fake_chain["top_up"][0]["additional"] == 1_000_000

    async def test_voucher_raises_cached_cumulative(self) -> None:
        cached = entry_for(cumulative=100)
        sink, updates = sink_for()
        await persist_channel(sink.store, cached)

        def voucher(amount: str) -> SessionContext:
            return SessionContext(
                action="voucher", descriptor=cached.descriptor, cumulative_amount_raw=amount
            )

        payload = await execute_credential_plan(await self._plan(voucher("250")), sink)
        assert payload.action == "voucher" and payload.cumulative_amount == "250"
        assert updates[-1].cumulative_amount == 250
        # A lower manual voucher never lowers the cached boundary.
        await execute_credential_plan(await self._plan(voucher("150")), sink)
        assert updates[-1].cumulative_amount == 250

    async def test_voucher_for_another_channel_leaves_cache(self) -> None:
        cached = entry_for(cumulative=100)
        sink, updates = sink_for()
        await persist_channel(sink.store, cached)
        plan = await self._plan(
            SessionContext(action="voucher", descriptor=descriptor_for(), cumulative_amount_raw="5")
        )
        await execute_credential_plan(plan, sink)
        assert updates == []
        cached_now = await store_get(sink.store, KEY)
        assert cached_now is not None and cached_now.cumulative_amount == 100


# ── store ─────────────────────────────────────────────────────────


class TestStore:
    async def test_async_json_store(self) -> None:
        kv = AsyncKv()
        store = create_json_channel_store(kv)
        assert await store.get(KEY) is None
        entry = entry_for()
        entry.uncertain_top_up = True
        await store.set(entry)
        assert serialize_entry(entry)["uncertainTopUp"] is True
        assert await store.get(entry_key(entry)) == entry
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
        await delete_channel(store, KEY)
        assert store.get(KEY) is stale
        with pytest.raises(UncertainFundingError, match="before replacing the channel"):
            await persist_channel(store, entry_for())
        stale.uncertain_top_up = False
        await delete_channel(store, KEY)
        assert store.get(KEY) is None

    async def test_view_shares_funding_lock_with_backing_store(self) -> None:
        backing = create_channel_store()
        view = create_channel_store()
        register_funding_store(view, backing)

        async def operation() -> str:
            # The view's funding lock is the backing store's, held while this runs.
            assert store_lock(backing, f"funding:{KEY}").locked()
            return "ok"

        assert await with_funding_lock(view, KEY, operation) == "ok"


# ── session method: management helpers ────────────────────────────


def receipt_header(channel_id: str) -> str:
    return serialize_session_receipt(
        create_session_receipt(
            challenge_id="c", channel_id=channel_id, accepted_cumulative=100, spent=0
        )
    )


async def _credential(challenge: Challenge, _: SessionContext) -> str:
    return f"Payment {challenge.id}"


class TestManagementHelpers:
    def test_headers_for_custom_credential_header(self) -> None:
        custom = replace(make_challenge(), header="Payment-Authorization")
        headers = management_headers(custom, "Payment abc", "Bearer token")
        assert headers["payment-authorization"] == "Payment abc"
        assert headers["authorization"] == "Bearer token"
        # A Payment credential in Authorization is never forwarded alongside a new one.
        assert "authorization" not in management_headers(custom, "Payment abc", "Payment old")
        headers = management_headers(make_challenge(), "Payment abc", "Bearer token")
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
        assert [c.id for c in session_challenges(response)] == [session_challenge.id]

    def test_read_receipt(self) -> None:
        assert read_receipt(httpx.Response(200)) is None
        assert read_receipt(httpx.Response(200, headers={"Payment-Receipt": "%%%"})) is None
        header = receipt_header("0x" + "aa" * 32)
        receipt = read_receipt(httpx.Response(200, headers={"Payment-Receipt": header}))
        assert receipt is not None and receipt.channel_id == "0x" + "aa" * 32

    async def test_post_retries_once_on_fresh_challenge(self) -> None:
        first, fresh = make_challenge(), make_challenge()
        seen: list[Challenge] = []
        sent: list[httpx.Request] = []

        async def send(request: httpx.Request) -> httpx.Response:
            sent.append(request)
            if len(sent) == 1:
                return httpx.Response(
                    402, headers={"WWW-Authenticate": fresh.to_www_authenticate("api.test")}
                )
            return httpx.Response(204)

        response = await post_management_credential(
            challenge=first,
            context=SessionContext(action="close"),
            create_session_credential=_credential,
            send=send,
            url="http://api.test/paid?x=1#frag",
            on_challenge=seen.append,
        )
        assert response.status_code == 204
        assert [r.headers["authorization"] for r in sent] == [
            f"Payment {first.id}",
            f"Payment {fresh.id}",
        ]
        assert [c.id for c in seen] == [fresh.id]
        assert str(sent[0].url) == "http://api.test/paid?x=1"
        # The retry needs no observer.
        sent.clear()
        response = await post_management_credential(
            challenge=first,
            context=SessionContext(action="close"),
            create_session_credential=_credential,
            send=send,
            url="http://api.test/paid",
        )
        assert response.status_code == 204 and len(sent) == 2

    async def test_post_returns_402_without_session_challenge(self) -> None:
        async def send(request: httpx.Request) -> httpx.Response:
            return httpx.Response(402)

        response = await post_management_credential(
            challenge=make_challenge(),
            context=SessionContext(action="close"),
            create_session_credential=_credential,
            send=send,
            url="http://api.test/paid",
        )
        assert response.status_code == 402

    async def test_close_transport_errors_propagate_unchanged(self) -> None:
        async def send(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        with pytest.raises(httpx.ConnectError):
            await post_management_credential(
                challenge=make_challenge(),
                context=SessionContext(action="close"),
                create_session_credential=_credential,
                send=send,
                url="http://api.test/paid",
            )


# ── session method: configuration and automatic top-up ────────────


def _ok_fetch(log: list[httpx.Request]) -> Any:
    async def fetch(request: httpx.Request) -> httpx.Response:
        log.append(request)
        return httpx.Response(204, request=request)

    return fetch


class TestSessionMethodUnits:
    def test_allowed_chain_ids_must_be_a_sequence_of_ids(self) -> None:
        with pytest.raises(ValueError, match="sequence of chain IDs"):
            SessionMethod(account=ACCOUNT, allowed_chain_ids="4217")  # pyright: ignore[reportArgumentType]
        assert SessionMethod(account=ACCOUNT, allowed_chain_ids=[4217]).allowed_chain_ids == (4217,)

    async def test_rejects_foreign_context_type(self) -> None:
        method = SessionMethod(account=ACCOUNT)
        with pytest.raises(TypeError, match="must be a SessionContext"):
            await method.create_credential(
                CredentialParams(challenge=make_challenge(), context={"action": "open"})
            )

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

    async def test_open_with_foreign_descriptor_context(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
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

    async def test_foreign_cached_channel_is_not_topped_up(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        store = create_channel_store()
        store.set(entry_for(cumulative=1000, deposit=1000, account=OTHER))
        method = SessionMethod(account=ACCOUNT, channel_store=store)
        log: list[httpx.Request] = []
        opened = payload_of(
            await method.create_credential(
                CredentialParams(
                    challenge=make_challenge(),
                    request=httpx.Request("GET", "http://api.test/paid"),
                    fetch=_ok_fetch(log),
                )
            )
        )
        assert opened["action"] == "open" and log == []

    async def test_snapshot_for_other_channel_is_ignored(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = SessionMethod(account=ACCOUNT)
        await method.create_credential(
            CredentialParams(challenge=make_challenge(suggested_deposit="1000"))
        )
        challenge = with_details(
            make_challenge(),
            sessionSnapshot=snapshot_wire(entry_for(), required=5000, deposit=9000),
        )
        voucher = payload_of(await method.create_credential(CredentialParams(challenge=challenge)))
        assert voucher["action"] == "voucher" and voucher["cumulativeAmount"] == "200"

    async def test_snapshot_deposit_is_adopted_without_top_up(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        updates: list[ChannelEntry] = []
        method = SessionMethod(account=ACCOUNT, on_channel_update=updates.append)
        await method.create_credential(CredentialParams(challenge=make_challenge()))
        channel = updates[-1]

        def challenge(required: int) -> Challenge:
            return with_details(
                make_challenge(),
                sessionSnapshot=snapshot_wire(channel, required=required, deposit=5000),
            )

        # Without a request to top up through, the larger server deposit still covers it.
        voucher = payload_of(
            await method.create_credential(CredentialParams(challenge=challenge(200)))
        )
        assert voucher["cumulativeAmount"] == "200"
        log: list[httpx.Request] = []
        await method.create_credential(
            CredentialParams(
                challenge=challenge(300),
                request=httpx.Request("GET", "http://api.test/paid"),
                fetch=_ok_fetch(log),
            )
        )
        assert log == []  # no top-up POST: the server deposit covers the voucher
        assert updates[-1].deposit == 5000
        assert fake_chain["top_up"] == []

    async def test_top_up_not_needed_returns_without_post(self) -> None:
        store = create_channel_store()
        channel = entry_for(cumulative=100, deposit=1000)
        store.set(channel)
        method = SessionMethod(account=ACCOUNT, channel_store=store)
        log: list[httpx.Request] = []
        receipt = await method.top_up_channel_if_needed(
            challenge=make_challenge(),
            channel=channel,
            deposit=500,
            required_cumulative=200,
            url="http://api.test/paid",
            send=_ok_fetch(log),
        )
        assert receipt is None and log == []

    async def test_top_up_for_uncached_channel_uses_given_entry(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
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
            url="http://api.test/paid",
            send=_ok_fetch(log),
        )
        (post,) = log
        top_up = payload_of(post.headers["authorization"])
        assert top_up["channelId"] == channel.channel_id and top_up["additionalDeposit"] == "200"
        assert updates[-1].channel_id == channel.channel_id and updates[-1].deposit == 300

    async def test_post_top_up_refuses_unresolved_channel(self) -> None:
        channel = entry_for()
        channel.uncertain_top_up = True
        method = SessionMethod(account=ACCOUNT)
        with pytest.raises(UncertainFundingError, match="before another top-up"):
            await method.post_top_up(
                challenge=make_challenge(),
                channel=channel,
                additional_deposit=1,
                url="http://api.test/paid",
                send=_ok_fetch([]),
            )

    async def test_top_up_returns_receipt(self, fake_chain: dict[str, list[Any]]) -> None:
        channel = entry_for()
        method = SessionMethod(account=ACCOUNT)

        async def send(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                204, headers={"Payment-Receipt": receipt_header(channel.channel_id)}
            )

        receipt = await method.post_top_up(
            challenge=make_challenge(),
            channel=channel,
            additional_deposit=10,
            url="http://api.test/paid",
            send=send,
        )
        assert receipt is not None and receipt.channel_id == channel.channel_id
