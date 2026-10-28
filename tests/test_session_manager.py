"""Unit tests for the TIP-1034 session manager (ports of mppx SessionManager tests): receipt
tracking, rollback of rejected requests, top-up and close edge cases, close snapshots and
unknown funding outcomes. HTTP goes through httpx.MockTransport and chain access is faked."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.errors import PaymentOutcomeUnknownError
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo.session.client import (
    ChannelEntry,
    PaymentResponse,
    SessionManager,
    UncertainFundingError,
    create_channel_store,
)
from mpp.methods.tempo.session.client.manager import (
    _FetchUse,  # pyright: ignore[reportPrivateUsage]
    is_expected_close_receipt,
)
from mpp.methods.tempo.session.protocol import (
    ChannelDescriptor,
    create_session_receipt,
    serialize_session_receipt,
)
from tests import test_session_client as client_tests
from tests.test_session_client import (
    ACCOUNT,
    FakeSessionServer,
    entry_for,
    make_challenge,
    payload_of,
)

fake_chain = client_tests.fake_chain
URL = "http://api.test/paid"
TX_HASH = "0x" + "ee" * 32


def receipt_header(
    *,
    channel_id: str,
    accepted: int,
    spent: int,
    challenge_id: str = "c",
    tx_hash: str | None = None,
) -> dict[str, str]:
    receipt = create_session_receipt(
        challenge_id=challenge_id,
        channel_id=channel_id,
        accepted_cumulative=accepted,
        spent=spent,
        tx_hash=tx_hash,
    )
    return {"Payment-Receipt": serialize_session_receipt(receipt)}


def challenge_response(challenge: Challenge, **kwargs: Any) -> httpx.Response:
    headers = {"WWW-Authenticate": challenge.to_www_authenticate("api.test")}
    return httpx.Response(402, headers=headers, **kwargs)


def with_snapshot(
    channel: ChannelEntry,
    *,
    accepted: int,
    spent: int,
    channel_id: str | None = None,
    descriptor: ChannelDescriptor | None = None,
) -> Challenge:
    challenge = make_challenge()
    request = dict(challenge.request)
    request["methodDetails"] = {
        **request["methodDetails"],
        "sessionSnapshot": {
            "channelId": channel_id or channel.channel_id,
            "descriptor": (descriptor or channel.descriptor).to_wire(),
            "acceptedCumulative": str(accepted),
            "requiredCumulative": str(accepted),
            "spent": str(spent),
            "deposit": str(channel.deposit),
        },
    }
    return replace(challenge, request=request)


def action_of(request: httpx.Request) -> str | None:
    authorization = request.headers.get("authorization")
    return payload_of(authorization)["action"] if authorization else None


def manager_for(handler: Any, **kwargs: Any) -> SessionManager:
    return SessionManager(account=ACCOUNT, transport=httpx.MockTransport(handler), **kwargs)


# ── helpers ───────────────────────────────────────────────────────


class TestHelpers:
    def test_payment_response_delegates_to_response(self) -> None:
        response = httpx.Response(201, headers={"X-Test": "1"}, json={"ok": True})
        wrapped = PaymentResponse(
            response=response, receipt=None, challenge=None, channel_id=None, cumulative=0
        )
        assert wrapped.status_code == 201
        assert wrapped.headers["x-test"] == "1"
        assert wrapped.json() == {"ok": True} and wrapped.is_success

    def test_expected_close_receipt(self) -> None:
        channel_id = "0x" + "aa" * 32

        def receipt(accepted: str = "200", spent: str = "150", tx_hash: str | None = TX_HASH):
            return replace(
                create_session_receipt(
                    challenge_id="c",
                    channel_id=channel_id,
                    accepted_cumulative=0,
                    spent=0,
                    tx_hash=tx_hash,
                ),
                accepted_cumulative=accepted,
                spent=spent,
            )

        expected: dict[str, Any] = {
            "challenge_id": "c",
            "channel_id": channel_id,
            "expected_close_amount": "200",
        }
        assert is_expected_close_receipt(receipt(), **expected)
        assert is_expected_close_receipt(receipt(), **expected, minimum_spent=150)
        assert not is_expected_close_receipt(receipt(), **expected, minimum_spent=151)
        assert not is_expected_close_receipt(receipt(spent="201"), **expected)
        assert not is_expected_close_receipt(receipt(spent="-1"), **expected)
        assert not is_expected_close_receipt(receipt(tx_hash=None), **expected)
        assert not is_expected_close_receipt(receipt(accepted="199"), **expected)
        assert not is_expected_close_receipt(
            receipt(), **{**expected, "expected_close_amount": "2e2"}
        )
        assert not is_expected_close_receipt(receipt(), **{**expected, "challenge_id": "d"})


# ── state and receipts ────────────────────────────────────────────


class TestState:
    async def test_initial_state(self) -> None:
        async with manager_for(FakeSessionServer().handler) as manager:
            with pytest.raises(ValueError, match="Cannot close session: no open channel"):
                await manager.close()
            assert manager.channel is None and manager.channel_id is None
            assert (manager.cumulative, manager.deposit, manager.spent) == (0, 0, 0)
            assert not manager.opened and manager.last_challenge is None

    async def test_out_of_band_credentials_track_channel(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        async with manager_for(FakeSessionServer().handler) as manager:
            method = manager._method  # pyright: ignore[reportPrivateUsage]
            await method.create_session_credential(make_challenge(suggested_deposit="500"))
            assert manager.opened and manager.deposit == 500 and manager.cumulative == 100
            # Without a request, there is no challenge or URL to post management credentials to.
            for operation in (lambda: manager.top_up(1), manager.close):
                with pytest.raises(ValueError, match="no challenge available"):
                    await operation()
            manager._last_challenge = make_challenge()  # pyright: ignore[reportPrivateUsage]
            for operation in (lambda: manager.top_up(1), manager.close):
                with pytest.raises(ValueError, match="no URL available"):
                    await operation()

    async def test_only_session_challenges_are_remembered(self) -> None:
        async with manager_for(FakeSessionServer().handler) as manager:
            observe = manager._on_challenge_received  # pyright: ignore[reportPrivateUsage]
            await observe({"challenge": make_challenge(protocol="v1")})
            await observe("not a payload")
            assert manager.last_challenge is None
            session_challenge = make_challenge()
            await observe({"challenge": session_challenge})
            assert manager.last_challenge is session_challenge

    async def test_receipts_for_other_channels_are_ignored(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "authorization" not in request.headers:
                return challenge_response(make_challenge())
            headers = receipt_header(channel_id="0x" + "aa" * 32, accepted=100, spent=100)
            return httpx.Response(200, headers=headers)

        async with manager_for(handler) as manager:
            response = await manager.fetch(URL)
            assert response.receipt is not None and manager.spent == 0
            assert response.channel_id == manager.channel_id is not None

    async def test_receipt_spending_more_than_accepted_is_rejected(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "authorization" not in request.headers:
                return challenge_response(make_challenge())
            channel_id = payload_of(request.headers["authorization"])["channelId"]
            return httpx.Response(
                200, headers=receipt_header(channel_id=channel_id, accepted=100, spent=150)
            )

        async with manager_for(handler) as manager:
            with pytest.raises(ValueError, match="spent exceeds accepted"):
                await manager.fetch(URL)

    @pytest.mark.parametrize("max_deposit", [None, "1"])
    async def test_receipt_beyond_local_voucher_state_is_rejected(
        self, fake_chain: dict[str, list[Any]], max_deposit: str | None
    ) -> None:
        # mppx assertReceiptWithinLocalState: a receipt never raises the signing boundary,
        # even below max_deposit.
        def handler(request: httpx.Request) -> httpx.Response:
            if "authorization" not in request.headers:
                return challenge_response(make_challenge())
            channel_id = payload_of(request.headers["authorization"])["channelId"]
            return httpx.Response(
                200, headers=receipt_header(channel_id=channel_id, accepted=5000, spent=5000)
            )

        async with manager_for(handler, max_deposit=max_deposit) as manager:
            with pytest.raises(ValueError, match="exceeds local voucher state"):
                await manager.fetch(URL)
            assert manager.spent == 0


# ── rollback ──────────────────────────────────────────────────────


class TestRollback:
    async def test_rejected_voucher_restores_boundary(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = FakeSessionServer(suggested_deposit="1000")
        reject = False

        def handler(request: httpx.Request) -> httpx.Response:
            if reject and action_of(request) == "voucher":
                return httpx.Response(400, json={"error": "rejected"})
            return server.handler(request)

        store = create_channel_store()
        async with manager_for(handler, channel_store=store) as manager:
            await manager.fetch(URL)
            channel_id = manager.channel_id
            reject = True
            response = await manager.fetch(URL)
            assert response.status_code == 400 and response.receipt is None
            assert response.cumulative == manager.cumulative == 100
            assert manager.channel_id == channel_id
            (cached,) = store._channels.values()  # pyright: ignore[reportPrivateUsage]
            assert cached.cumulative_amount == 100
            # The next request signs from the restored boundary.
            reject = False
            assert (await manager.fetch(URL)).cumulative == 200

    async def test_transport_error_discards_opened_channel(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "authorization" not in request.headers:
                return challenge_response(make_challenge())
            raise httpx.ConnectError("connection reset", request=request)

        store = create_channel_store()
        async with manager_for(handler, channel_store=store) as manager:
            with pytest.raises(PaymentOutcomeUnknownError):
                await manager.fetch(URL)
            assert manager.channel_id is None
            assert not store._channels  # pyright: ignore[reportPrivateUsage]

    async def test_unpaid_error_response_changes_nothing(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="down")

        async with manager_for(handler) as manager:
            response = await manager.fetch(URL)
            assert response.status_code == 503 and response.text == "down"
            assert response.channel_id is None and response.cumulative == 0

    async def test_rollback_keeps_channel_with_unknown_funding(self) -> None:
        async with manager_for(FakeSessionServer().handler) as manager:
            entry = entry_for()
            entry.uncertain_top_up = True
            manager._use = _FetchUse(  # pyright: ignore[reportPrivateUsage]
                previous=None, previous_spent=0, created=[entry]
            )
            with pytest.raises(UncertainFundingError, match="before discarding"):
                await manager._rollback()  # pyright: ignore[reportPrivateUsage]


# ── top-up ────────────────────────────────────────────────────────


class TestTopUp:
    async def test_amount_validation(self, fake_chain: dict[str, list[Any]]) -> None:
        async with manager_for(
            FakeSessionServer(suggested_deposit="1000").handler, max_deposit="0.001"
        ) as manager:
            await manager.fetch(URL)
            for amount in (0, "0", -5):
                with pytest.raises(ValueError, match="greater than zero"):
                    await manager.top_up(amount)
            with pytest.raises(ValueError, match="exceeds local maxDeposit"):
                await manager.top_up(901)
            await manager.top_up(900)  # raw units
            assert manager.deposit == 1900

    async def test_retries_on_fresh_challenge(self, fake_chain: dict[str, list[Any]]) -> None:
        server = FakeSessionServer(suggested_deposit="1000")
        fresh = make_challenge()
        posts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                posts.append(
                    Credential.from_authorization(request.headers["authorization"]).challenge.id
                )
                if len(posts) == 1:
                    return challenge_response(fresh)
            return server.handler(request)

        async with manager_for(handler) as manager:
            await manager.fetch(URL)
            receipt = await manager.top_up("0.0005")
            assert receipt is not None and manager.deposit == 1500
            last = manager.last_challenge
            assert posts[1] == fresh.id and last is not None and last.id == fresh.id

    async def test_failed_request_blocks_further_funding(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = FakeSessionServer(suggested_deposit="1000")

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                raise httpx.ReadTimeout("timed out", request=request)
            return server.handler(request)

        store = create_channel_store()
        async with manager_for(handler, channel_store=store) as manager:
            await manager.fetch(URL)
            with pytest.raises(UncertainFundingError):
                await manager.top_up(500)
            (cached,) = store._channels.values()  # pyright: ignore[reportPrivateUsage]
            assert cached.uncertain_top_up
            with pytest.raises(UncertainFundingError):
                await manager.fetch(URL)
            with pytest.raises(UncertainFundingError):
                await manager.top_up(500)

    async def test_automatic_top_up_failure_blocks_fetch(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = FakeSessionServer()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                raise httpx.ReadTimeout("timed out", request=request)
            return server.handler(request)

        async with manager_for(handler) as manager:
            await manager.fetch(URL)  # opens with a one-request deposit
            with pytest.raises(UncertainFundingError):
                await manager.fetch(URL)
            assert manager.channel is not None and manager.channel.uncertain_top_up
            with pytest.raises(UncertainFundingError):
                await manager.fetch(URL)

    async def test_channel_switched_during_top_up_is_left_alone(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = FakeSessionServer(suggested_deposit="1000")
        other = entry_for(deposit=50)
        manager = manager_for(lambda request: handle(request))

        def handle(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                # A concurrent request moved the manager to another channel.
                manager._channel = other  # pyright: ignore[reportPrivateUsage]
            return server.handler(request)

        async with manager:
            await manager.fetch(URL)
            await manager.top_up(100)
            assert manager.channel is other and other.deposit == 50


# ── close ─────────────────────────────────────────────────────────


class TestClose:
    async def test_close_at_fresh_snapshot_amount(self, fake_chain: dict[str, list[Any]]) -> None:
        server = FakeSessionServer(suggested_deposit="1000")
        snapshot: list[Challenge] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if action_of(request) == "close" and not snapshot:
                channel = manager.channel
                assert channel is not None
                snapshot.append(with_snapshot(channel, accepted=200, spent=200))
                return challenge_response(snapshot[0])
            return server.handler(request)

        manager = manager_for(handler)
        async with manager:
            await manager.fetch(URL)
            await manager.fetch(URL)
            receipt = await manager.close()
            assert receipt is not None and receipt.challenge_id == snapshot[0].id
            assert receipt.accepted_cumulative == "200" and manager.spent == 200
            last = manager.last_challenge
            assert last is not None and last.id == snapshot[0].id

    async def test_close_amount_validates_snapshot(self, fake_chain: dict[str, list[Any]]) -> None:
        async with manager_for(FakeSessionServer(suggested_deposit="1000").handler) as manager:
            await manager.fetch(URL)
            await manager.fetch(URL)
            channel = manager.channel
            assert channel is not None
            close_amount = manager._close_amount  # pyright: ignore[reportPrivateUsage]
            other = entry_for()
            cases = [
                (
                    with_snapshot(channel, accepted=100, spent=0, descriptor=other.descriptor),
                    "descriptor does not match its channel ID",
                ),
                (
                    with_snapshot(
                        channel,
                        accepted=100,
                        spent=0,
                        channel_id=other.channel_id,
                        descriptor=other.descriptor,
                    ),
                    "does not match local session",
                ),
                (with_snapshot(channel, accepted=100, spent=150), "spent exceeds accepted"),
                (with_snapshot(channel, accepted=300, spent=0), "exceeds local voucher state"),
            ]
            for challenge, message in cases:
                with pytest.raises(ValueError, match=message):
                    close_amount(channel, challenge, False)
            # Applying a snapshot below the spend receipts already confirmed is refused.
            assert manager.spent == 200
            below = with_snapshot(channel, accepted=150, spent=100)
            assert close_amount(channel, below, False) == 150
            with pytest.raises(ValueError, match="below locally confirmed spend"):
                close_amount(channel, below, True)
            assert close_amount(channel, make_challenge(), True) == 200

    @pytest.mark.parametrize(
        ("reply", "message"),
        [
            (
                httpx.Response(402, headers={"WWW-Authenticate": 'Bearer realm="x"'}, text="no"),
                'Close request failed with status 402: no [WWW-Authenticate: Bearer realm="x"]',
            ),
            (httpx.Response(500), "Close request failed with status 500"),
        ],
    )
    async def test_failed_close_reports_status_body_and_challenge(
        self, fake_chain: dict[str, list[Any]], reply: httpx.Response, message: str
    ) -> None:
        server = FakeSessionServer(suggested_deposit="1000")

        def handler(request: httpx.Request) -> httpx.Response:
            return reply if action_of(request) == "close" else server.handler(request)

        async with manager_for(handler) as manager:
            await manager.fetch(URL)
            with pytest.raises(RuntimeError) as raised:
                await manager.close()
            assert str(raised.value) == message

    async def test_close_without_receipt(self, fake_chain: dict[str, list[Any]]) -> None:
        server = FakeSessionServer(suggested_deposit="1000")

        def handler(request: httpx.Request) -> httpx.Response:
            if action_of(request) == "close":
                return httpx.Response(204)
            return server.handler(request)

        async with manager_for(handler) as manager:
            await manager.fetch(URL)
            assert await manager.close() is None

    @pytest.mark.parametrize(
        ("accepted", "tx_hash"),
        [(999, TX_HASH), (100, None), (100, "0x1234"), (100, "0x" + "zz" * 32)],
    )
    async def test_mismatched_close_receipt_rejected(
        self, fake_chain: dict[str, list[Any]], accepted: int, tx_hash: str | None
    ) -> None:
        server = FakeSessionServer(suggested_deposit="1000")

        def handler(request: httpx.Request) -> httpx.Response:
            if action_of(request) == "close":
                credential = Credential.from_authorization(request.headers["authorization"])
                headers = receipt_header(
                    channel_id=credential.payload["channelId"],
                    challenge_id=credential.challenge.id,
                    accepted=accepted,
                    spent=100,
                    tx_hash=tx_hash,
                )
                return httpx.Response(204, headers=headers)
            return server.handler(request)

        async with manager_for(handler) as manager:
            await manager.fetch(URL)
            with pytest.raises(ValueError, match="mismatched payment receipt"):
                await manager.close()


async def test_manager_for_other_account_opens_its_own_channel(
    fake_chain: dict[str, list[Any]],
) -> None:
    other = TempoAccount.from_key("0x" + "cd" * 32)
    async with SessionManager(
        account=other, transport=httpx.MockTransport(FakeSessionServer().handler)
    ) as manager:
        response = await manager.fetch(URL)
        assert response.status_code == 200
        assert manager.channel is not None and manager.channel.descriptor.payer == other.address
