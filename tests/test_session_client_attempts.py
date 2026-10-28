"""Credential lifecycle tests for the TIP-1034 session client (ports of mppx Session.ts
deferred opens, Fetch.ts attempt settlement and SessionManager.ts retry challenges), plus
cancelled top-ups and channel stores without hashing or weak references."""

from __future__ import annotations

import asyncio
import base64
import gc
import sys
from dataclasses import dataclass, field, replace
from typing import Any, cast

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.client.transport import (
    PaymentTransport,
    _accepted_keywords,  # pyright: ignore[reportPrivateUsage]
    _response_challenges,  # pyright: ignore[reportPrivateUsage]
)
from mpp.errors import PaymentOutcomeUnknownError
from mpp.events import CREDENTIAL_CREATED
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo.session.client import (
    ChannelEntry,
    SessionManager,
    SessionMethod,
    UncertainFundingError,
    create_channel_store,
)
from mpp.methods.tempo.session.client.manager import (
    _FetchUse,  # pyright: ignore[reportPrivateUsage]
)
from mpp.methods.tempo.session.client.session import (
    _acknowledges_open,  # pyright: ignore[reportPrivateUsage]
    _matches_open,  # pyright: ignore[reportPrivateUsage]
    _PendingOpenStore,  # pyright: ignore[reportPrivateUsage]
    post_management_credential,
)
from mpp.methods.tempo.session.client.state import SessionContext
from mpp.methods.tempo.session.client.store import (
    _StoreMap,  # pyright: ignore[reportPrivateUsage]
    entry_key,
    store_get,
    store_lock,
    with_funding_lock,
)
from mpp.methods.tempo.session.protocol import (
    create_session_receipt,
    serialize_session_receipt,
)
from mpp.runtime import (
    AttemptOutcome,
    ClientMethod,
    CredentialParams,
    PaymentAttempt,
    PaymentRuntime,
)
from tests import test_session_client as client_tests
from tests.test_session_client import ACCOUNT, entry_for, make_challenge, payload_of

fake_chain = client_tests.fake_chain
URL = "http://api.test/paid"


def required(challenge: Challenge) -> httpx.Response:
    return httpx.Response(
        402, headers={"WWW-Authenticate": challenge.to_www_authenticate("api.test")}
    )


def paid(credential: Credential, status: int = 200) -> httpx.Response:
    payload = credential.payload
    receipt = create_session_receipt(
        challenge_id=credential.challenge.id,
        channel_id=payload["channelId"],
        accepted_cumulative=int(payload["cumulativeAmount"]),
        spent=0,
    )
    return httpx.Response(status, headers={"Payment-Receipt": serialize_session_receipt(receipt)})


def snapshot_challenge(
    channel_id: str, accepted: int, entry: ChannelEntry | None = None
) -> Challenge:
    challenge = make_challenge()
    request = dict(challenge.request)
    request["methodDetails"] = {
        **request["methodDetails"],
        "sessionSnapshot": {
            "channelId": channel_id,
            "descriptor": (entry or entry_for()).descriptor.to_wire(),
            "acceptedCumulative": str(accepted),
            "requiredCumulative": str(accepted),
            "spent": "0",
            "deposit": "1000",
        },
    }
    return replace(challenge, request=request)


class Server:
    """Answers unpaid requests with a challenge and paid ones from a script."""

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


# ── plain transport: deferred opens (mppx Session.ts) ──────────────


class TestDeferredOpen:
    async def test_rejected_open_is_not_stored(self, fake_chain: dict[str, list[Any]]) -> None:
        # A replacement challenge rejects the open: the next credential opens again
        # instead of signing a voucher for a channel the server never opened.
        server = Server(lambda _: required(make_challenge()))
        method = SessionMethod(account=ACCOUNT)
        response = await get(transport_for(server, method))
        assert response.status_code == 200
        first, second = server.payloads
        assert (first["action"], second["action"]) == ("open", "open")
        entry = stored(method)
        assert entry is not None and entry.channel_id == second["channelId"]
        assert entry.cumulative_amount == 100

    @pytest.mark.parametrize("status", [500, 403, 307])
    async def test_unaccepted_open_is_discarded(
        self, fake_chain: dict[str, list[Any]], status: int
    ) -> None:
        server = Server(httpx.Response(status, headers={"Location": "http://api.test/other"}))
        method = SessionMethod(account=ACCOUNT)
        transport = transport_for(server, method)
        assert (await get(transport)).status_code == status
        assert stored(method) is None
        # The scope lock was released: the next request opens a channel.
        assert (await get(transport)).status_code == 200
        assert [p["action"] for p in server.payloads] == ["open", "open"]
        assert stored(method) is not None

    async def test_failed_send_discards_open(self, fake_chain: dict[str, list[Any]]) -> None:
        server = Server(httpx.ConnectError("reset"))
        method = SessionMethod(account=ACCOUNT)
        with pytest.raises(PaymentOutcomeUnknownError):
            await get(transport_for(server, method))
        assert stored(method) is None
        assert (await get(transport_for(server, method))).status_code == 200

    async def test_identical_challenge_resends_the_credential(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
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

    async def test_repeated_challenges_exhaust_and_discard(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = Server()
        server.script = [lambda _: required(server.challenge)] * 3
        method = SessionMethod(account=ACCOUNT)
        response = await get(transport_for(server, method))
        assert response.status_code == 402
        assert len(set(server.authorizations)) == 1 and stored(method) is None

    async def test_snapshot_acknowledges_open(self, fake_chain: dict[str, list[Any]]) -> None:
        server = Server(
            lambda credential: required(snapshot_challenge(credential.payload["channelId"], 100))
        )
        method = SessionMethod(account=ACCOUNT)
        assert (await get(transport_for(server, method))).status_code == 200
        first, second = server.payloads
        assert (first["action"], second["action"]) == ("open", "voucher")
        assert first["channelId"] == second["channelId"]
        assert second["cumulativeAmount"] == "200"

    async def test_accepted_open_already_stored_is_kept(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = SessionMethod(account=ACCOUNT)
        attempt = PaymentAttempt()
        credential = await method.create_credential(
            CredentialParams(challenge=make_challenge(), attempt=attempt)
        )
        assert stored(method) is None and attempt.settle is not None
        updates: list[ChannelEntry] = []
        method.on_channel_update = updates.append
        channel_id = payload_of(credential)["channelId"]
        current = replace(entry_for(cumulative=500), channel_id=channel_id)
        method.store.set(current)
        # The same channel is already stored (and further along): nothing is replaced.
        assert await attempt.settle(AttemptOutcome(status="accepted"))
        assert stored(method) is current and updates == []

    def test_acknowledgement_requires_matching_challenge_and_amount(self) -> None:
        entry = entry_for()
        challenge = make_challenge()

        def receipt(challenge_id: str, accepted: int) -> httpx.Response:
            value = create_session_receipt(
                challenge_id=challenge_id,
                channel_id=entry.channel_id,
                accepted_cumulative=accepted,
                spent=0,
            )
            return httpx.Response(
                402, headers={"Payment-Receipt": serialize_session_receipt(value)}
            )

        def outcome(**kwargs: Any) -> AttemptOutcome:
            return AttemptOutcome(status="rejected", **kwargs)

        assert _acknowledges_open(outcome(response=receipt(challenge.id, 100)), challenge, entry)
        assert not _acknowledges_open(outcome(response=receipt("other", 100)), challenge, entry)
        assert not _acknowledges_open(outcome(response=receipt(challenge.id, 99)), challenge, entry)
        assert not _acknowledges_open(outcome(response="not http"), challenge, entry)
        others = (make_challenge(protocol="v1"), make_challenge())
        assert not _acknowledges_open(outcome(challenges=others), challenge, entry)
        good = snapshot_challenge(entry.channel_id, 100)
        assert _acknowledges_open(outcome(challenges=(good,)), challenge, entry)
        assert not _matches_open(entry, entry.channel_id, "not a number")

    async def test_cancelled_credential_event_releases_the_scope(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
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
        response = await asyncio.wait_for(get(transport), 5)
        assert response.status_code == 200
        assert [p["action"] for p in server.payloads] == ["open"]

    async def test_malformed_receipt_releases_the_scope(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        # A receipt nested past the recursion limit is ignored like any malformed one.
        nested = base64.urlsafe_b64encode(b"[" * 100_000 + b"]" * 100_000).rstrip(b"=")
        server = Server(httpx.Response(403, headers={"Payment-Receipt": nested.decode()}))
        method = SessionMethod(account=ACCOUNT)
        transport = transport_for(server, method)
        assert (await get(transport)).status_code == 403
        assert stored(method) is None
        assert (await asyncio.wait_for(get(transport), 5)).status_code == 200

    async def test_failed_acknowledgement_check_releases_the_scope(
        self, fake_chain: dict[str, list[Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        method = SessionMethod(account=ACCOUNT)
        attempt = PaymentAttempt()
        challenge = make_challenge()
        await method.create_credential(CredentialParams(challenge=challenge, attempt=attempt))
        assert attempt.settle is not None

        def fail(*_: Any) -> bool:
            raise RuntimeError("boom")

        session_module = sys.modules["mpp.methods.tempo.session.client.session"]
        monkeypatch.setattr(session_module, "_acknowledges_open", fail)
        with pytest.raises(RuntimeError, match="boom"):
            await attempt.settle(AttemptOutcome(status="rejected"))
        key = entry_key(entry_for())
        lock = store_lock(method.store, f"channel:{key}")
        assert not lock.locked()

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


# ── manager: replacement challenges (mppx SessionManager onChallenge) ──


class TestManagerRetryChallenges:
    async def test_replacement_challenge_rolls_back_open(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = Server(lambda _: required(make_challenge()))
        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(server.handler)
        ) as manager:
            response = await manager.fetch(URL)
            assert response.status_code == 200
            first, second = server.payloads
            assert (first["action"], second["action"]) == ("open", "open")
            assert manager.channel_id == second["channelId"] and manager.cumulative == 100

    async def test_snapshot_commits_open(self, fake_chain: dict[str, list[Any]]) -> None:
        server = Server(
            lambda credential: required(snapshot_challenge(credential.payload["channelId"], 100)),
            httpx.Response(500),
        )
        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(server.handler)
        ) as manager:
            response = await manager.fetch(URL)
            # The committed open survives the voucher's failure; only the voucher is undone.
            assert response.status_code == 500
            first, second = server.payloads
            assert (first["action"], second["action"]) == ("open", "voucher")
            assert manager.channel_id == first["channelId"] and manager.cumulative == 100

    async def test_repeated_challenge_id_restores_voucher_boundary(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = Server()
        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(server.handler)
        ) as manager:
            await manager.fetch(URL)
            changed = replace(
                server.challenge, request={**server.challenge.request, "amount": "50"}
            )
            server.script = [lambda _: required(changed)]
            assert (await manager.fetch(URL)).status_code == 200
            amounts = [p["cumulativeAmount"] for p in server.payloads[1:]]
            assert amounts == ["200", "150"] and manager.cumulative == 150

    async def test_identical_challenge_resends_voucher(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = Server()
        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(server.handler)
        ) as manager:
            await manager.fetch(URL)
            server.script = [lambda _: required(server.challenge)]
            assert (await manager.fetch(URL)).status_code == 200
            assert server.authorizations[1] == server.authorizations[2]
            assert manager.cumulative == 200


class TestManagerRetryEdges:
    async def test_snapshot_for_another_channel_rolls_back_open(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        # Another payer's channel: the snapshot neither commits nor recovers it.
        other = entry_for(account=TempoAccount.from_key("0x" + "cd" * 32))
        server = Server(lambda _: required(snapshot_challenge(other.channel_id, 100, other)))
        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(server.handler)
        ) as manager:
            assert (await manager.fetch(URL)).status_code == 200
            assert [p["action"] for p in server.payloads] == ["open", "open"]

    async def test_fresh_challenge_on_voucher_retry_signs_again(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        # As in mppx, a replacement challenge with a new ID keeps the retried voucher.
        server = Server()
        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(server.handler)
        ) as manager:
            await manager.fetch(URL)
            server.script = [lambda _: required(make_challenge())]
            assert (await manager.fetch(URL)).status_code == 200
            amounts = [p["cumulativeAmount"] for p in server.payloads[1:]]
            assert amounts == ["200", "300"]

    async def test_identical_challenge_event_changes_nothing(self) -> None:
        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(Server().handler)
        ) as manager:
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


# ── cancelled top-ups (mppx abort → UncertainFundingError) ─────────


async def _hang(_: httpx.Request) -> httpx.Response:
    await asyncio.Event().wait()
    raise AssertionError("unreachable")


async def _credential(_: Challenge, __: SessionContext) -> str:
    return "Payment x"


class TestCancelledTopUp:
    async def test_cancelled_post_marks_funding_uncertain(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = SessionMethod(account=ACCOUNT)
        channel = entry_for()
        method.store.set(channel)
        task = asyncio.create_task(
            method.post_top_up(
                challenge=make_challenge(),
                channel=channel,
                additional_deposit=100,
                url=URL,
                send=_hang,
            )
        )
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        entry = await store_get(method.store, entry_key(channel))
        assert entry is not None and entry.uncertain_top_up

    @pytest.mark.parametrize("action", ["topUp", "close"])
    async def test_only_cancelled_top_up_requests_are_uncertain(self, action: Any) -> None:
        called: list[bool] = []

        async def mark() -> None:
            called.append(True)

        task = asyncio.create_task(
            post_management_credential(
                challenge=make_challenge(),
                context=SessionContext(action=action),
                create_session_credential=_credential,
                send=_hang,
                url=URL,
                on_cancelled_top_up=mark,
            )
        )
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert called == ([True] if action == "topUp" else [])

    async def test_manager_blocks_funding_after_cancelled_top_up(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = Server()
        hanging = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                hanging.set()
                await asyncio.Event().wait()
            return server.handler(request)

        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(handler)
        ) as manager:
            await manager.fetch(URL)
            task = asyncio.create_task(manager.top_up(100))
            await hanging.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(UncertainFundingError, match="cancelled"):
                await manager.fetch(URL)
            with pytest.raises(UncertainFundingError, match="cancelled"):
                await manager.top_up(100)

    async def test_manager_cancelled_automatic_top_up(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = Server(suggested_deposit=None)
        hanging = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                hanging.set()
                await asyncio.Event().wait()
            return server.handler(request)

        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(handler)
        ) as manager:
            await manager.fetch(URL)  # deposit 100: the next voucher needs a top-up
            task = asyncio.create_task(manager.fetch(URL))
            await hanging.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(UncertainFundingError, match="cancelled"):
                await manager.fetch(URL)

    async def test_manager_cancelled_fetch_without_funding(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        started = asyncio.Event()
        server = Server()

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.headers.get("x-hang"):
                started.set()
                await asyncio.Event().wait()
            return server.handler(request)

        async with SessionManager(
            account=ACCOUNT, transport=httpx.MockTransport(handler)
        ) as manager:
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


# ── stores without hashing or weak references ─────────────────────


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


class TestStores:
    @pytest.mark.parametrize("store_type", [DataclassStore, SlottedStore])
    async def test_session_accepts_any_store_object(
        self, fake_chain: dict[str, list[Any]], store_type: type[Any]
    ) -> None:
        store = store_type()
        server = Server()
        method = SessionMethod(account=ACCOUNT, channel_store=store)
        transport = transport_for(server, method)
        for _ in range(2):
            assert (await get(transport)).status_code == 200
        assert [p["action"] for p in server.payloads] == ["open", "voucher"]
        assert store_lock(store, "k") is store_lock(store, "k")

        async def operation() -> str:
            return "ok"

        assert await with_funding_lock(store, "k", operation) == "ok"

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


# ── transport compatibility ───────────────────────────────────────


class TestTransportCompatibility:
    async def test_runtime_with_old_create_credential_signature(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
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

        server = Server()
        method = SessionMethod(account=ACCOUNT)
        transport = PaymentTransport(
            runtime=OldRuntime([method.client_method()]),
            inner=httpx.MockTransport(server.handler),
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
