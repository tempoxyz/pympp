"""Voucher acceptance against recently verified state, and charging in the accepting update.

Covers tempo.session(voucher_state_max_age=..., charge_on_acceptance=...): mppx Session.ts and
CredentialVerification.ts (canUseStoredChannelState, acceptVoucherInOneUpdate,
recordOnChainReadInBackground, Settlement.shouldChargeVoucherOnAcceptance).
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from mpp.errors import VerificationFailedError
from mpp.methods.tempo.session.server import _settlement as settlement
from mpp.methods.tempo.session.server import _verification as verification
from mpp.methods.tempo.session.server._request_state import RequestProbe
from mpp.methods.tempo.session.server._schedule import SettlementSchedule
from mpp.methods.tempo.session.server._store import (
    ChannelClosedError,
    ChannelNotFoundError,
    ChannelState,
    DeltaTooSmallError,
    InsufficientBalanceError,
    InvalidSignatureError,
)
from mpp.server import PaymentRequired, PaymentVerified
from tests.session_helpers import Lifecycle, sign
from tests.test_session_chain import DEPOSIT, PAYEE, opened_log
from tests.test_session_server import decode_header, handler_for, opened, pay

MAX_AGE = 60_000


@pytest.fixture
async def life() -> Lifecycle:
    return await Lifecycle().build()


async def verified_now(life: Lifecycle) -> None:
    """Record the stored state as just read on chain, with no cached read in the method."""
    await life.update(on_chain_verified_at=verification._now_ms())  # pyright: ignore[reportPrivateUsage]
    life.last_verified.clear()


def reads(life: Lifecycle) -> int:
    return len(life.rpc.methods("eth_call"))


async def settle_background() -> None:
    while verification._background_reads:  # pyright: ignore[reportPrivateUsage]
        await asyncio.gather(*list(verification._background_reads))  # pyright: ignore[reportPrivateUsage]


class Wrapped:
    """A channel store that is not the pympp adapter, so it has no one-update acceptance."""

    def __init__(self, life: Lifecycle) -> None:
        self.life = life

    async def get_channel(self, channel_id: str) -> ChannelState | None:
        return await self.life.store.get_channel(channel_id)

    async def update_channel(self, channel_id: str, fn: Any) -> ChannelState | None:
        return await self.life.store.update_channel(channel_id, fn)


class TestVoucherStateMaxAge:
    async def test_recently_read_vouchers_are_accepted_without_a_chain_read(
        self, life: Lifecycle
    ) -> None:
        await life.open(100)
        before = reads(life)
        for amount in (200, 300, 400):
            receipt = await life.accept(life.voucher_payload(amount), voucher_state_max_age=MAX_AGE)
            assert receipt.accepted_cumulative == str(amount)
        await settle_background()
        assert reads(life) == before
        assert (await life.channel()).highest_voucher_amount == 400

    async def test_without_a_max_age_every_voucher_reads_the_chain(self, life: Lifecycle) -> None:
        await life.open(100)
        before = reads(life)
        for amount in (200, 300):
            await life.accept(life.voucher_payload(amount))
        assert reads(life) == before + 2

    async def test_a_stale_cache_starts_a_read_recorded_in_the_background(
        self, life: Lifecycle
    ) -> None:
        await life.open(100)
        await life.update(on_chain_verified_at=verification._now_ms() - 1_000)  # pyright: ignore[reportPrivateUsage]
        life.last_verified.clear()
        before = reads(life)
        # The stored state was verified within the max age, so the voucher does not wait.
        receipt = await life.accept(life.voucher_payload(200), voucher_state_max_age=MAX_AGE)
        assert receipt.accepted_cumulative == "200"
        await settle_background()
        assert reads(life) == before + 1
        channel = await life.channel()
        assert channel.on_chain_verified_at is not None
        assert channel.on_chain_verified_at >= verification._now_ms() - 1_000  # pyright: ignore[reportPrivateUsage]
        assert life.channel_id in life.last_verified

    async def test_a_background_read_records_a_pending_close_and_rejects_later_vouchers(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await opened(life, 100, spent=100)
        await verified_now(life)
        settled: list[str] = []

        async def fake_settle(*args: Any, **kwargs: Any) -> str:
            settled.append("settle")
            return "0x" + "ee" * 32

        monkeypatch.setattr(settlement, "settle", fake_settle)
        life.rpc.states[life.channel_id] = (0, DEPOSIT, 1_700_000_000)
        # Accepted against the stored state while the read finds the close request.
        receipt = await life.accept(life.voucher_payload(200), voucher_state_max_age=MAX_AGE)
        assert receipt.accepted_cumulative == "200"
        await settle_background()
        assert (await life.channel()).close_requested_at == 1_700_000_000
        assert settled == ["settle"]
        with pytest.raises(ChannelClosedError, match="pending close"):
            await life.accept(life.voucher_payload(300), voucher_state_max_age=MAX_AGE)

    async def test_background_reads_ignore_failures_and_unfunded_channels(
        self, life: Lifecycle
    ) -> None:
        await life.open(100)
        await verified_now(life)
        stored = await life.channel()
        life.rpc.states[life.channel_id] = (0, 0, 0)
        await life.accept(life.voucher_payload(200), voucher_state_max_age=MAX_AGE)
        await settle_background()
        assert (await life.channel()).on_chain_verified_at == stored.on_chain_verified_at

        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("node down")

        await verified_now(life)
        failing = httpx.AsyncClient(transport=httpx.MockTransport(down))
        receipt = await life.accept(
            life.voucher_payload(300), voucher_state_max_age=MAX_AGE, http_client=failing
        )
        assert receipt.accepted_cumulative == "300"
        await settle_background()

    async def test_a_background_read_leaves_a_closed_channel_alone(self, life: Lifecycle) -> None:
        await life.open(100)
        await verified_now(life)
        receipt = await life.accept(life.voucher_payload(200), voucher_state_max_age=MAX_AGE)
        await life.update(finalized=True)
        await settle_background()
        assert receipt.accepted_cumulative == "200"
        assert (await life.channel()).finalized

    async def test_vouchers_past_the_stored_deposit_wait_for_the_chain(
        self, life: Lifecycle
    ) -> None:
        await life.open(100)
        await life.update(deposit=250)
        before = reads(life)
        receipt = await life.accept(life.voucher_payload(300), voucher_state_max_age=MAX_AGE)
        assert receipt.accepted_cumulative == "300"
        assert reads(life) == before + 1
        assert (await life.channel()).deposit == DEPOSIT

    async def test_state_older_than_the_max_age_waits_for_the_chain(self, life: Lifecycle) -> None:
        await life.open(100)
        await life.update(on_chain_verified_at=1)
        life.last_verified.clear()
        life.rpc.states[life.channel_id] = (0, DEPOSIT, 1_700_000_000)
        with pytest.raises(ChannelClosedError, match="pending close"):
            await life.accept(life.voucher_payload(200), voucher_state_max_age=MAX_AGE)

    async def test_a_custom_channel_store_accepts_against_stored_state(
        self, life: Lifecycle
    ) -> None:
        await life.open(100)
        before = reads(life)
        receipt = await life.accept(
            life.voucher_payload(200), voucher_state_max_age=MAX_AGE, store=Wrapped(life)
        )
        assert receipt.accepted_cumulative == "200"
        assert reads(life) == before
        life.last_verified.clear()
        receipt = await life.accept(
            life.voucher_payload(300), voucher_state_max_age=MAX_AGE, store=Wrapped(life)
        )
        await settle_background()
        assert receipt.accepted_cumulative == "300" and reads(life) == before + 1

    @pytest.mark.parametrize(
        ("setup", "overrides", "error", "match"),
        [
            ({}, {"signer": PAYEE}, InvalidSignatureError, "signature"),
            ({"highest": 200}, {"amount": 200, "advance": True}, DeltaTooSmallError, "new funds"),
            ({"highest": 300}, {"amount": 200}, VerificationFailedError, "strictly greater"),
            ({"fields": {"finalized": True}}, {}, ChannelClosedError, "finalized"),
            ({"fields": {"backend": "contract"}}, {}, VerificationFailedError, "precompile"),
            ({"fields": {"descriptor": None}}, {}, VerificationFailedError, "precompile"),
            ({}, {"source": "did:pkh:eip155:1:0x1"}, VerificationFailedError, "source"),
            ({"delete": True}, {}, ChannelNotFoundError, "not found"),
        ],
    )
    async def test_one_update_rejections(
        self,
        life: Lifecycle,
        setup: dict[str, Any],
        overrides: dict[str, Any],
        error: type[Exception],
        match: str,
    ) -> None:
        await life.open(100)
        if "highest" in setup:
            await life.accept(life.voucher_payload(setup["highest"]))
        if setup.get("fields"):
            await life.update(**setup["fields"])
        if setup.get("delete"):
            await life.store.update_channel(life.channel_id, lambda current: None)
        life.last_verified.clear()
        amount = overrides.get("amount", 400)
        fields: dict[str, Any] = {}
        if "signer" in overrides:
            fields["signature"] = sign(life.channel_id, amount, overrides["signer"])
        context: dict[str, Any] = {"voucher_state_max_age": MAX_AGE}
        if overrides.get("advance"):
            context["require_voucher_advance"] = True
        if "source" in overrides:
            context["credential_source"] = overrides["source"]
        with pytest.raises(error, match=match):
            await life.accept(life.voucher_payload(amount, **fields), **context)
        # The cancelled chain read is not recorded.
        await settle_background()

    async def test_a_resent_voucher_changes_nothing(self, life: Lifecycle) -> None:
        await life.open(100)
        await life.accept(life.voucher_payload(200), voucher_state_max_age=MAX_AGE)
        receipt = await life.accept(life.voucher_payload(200), voucher_state_max_age=MAX_AGE)
        assert receipt.accepted_cumulative == "200" and receipt.spent == "0"

    async def test_validation_trusts_recently_verified_state(self, life: Lifecycle) -> None:
        await life.open(100)
        await verified_now(life)
        before = reads(life)
        context = life.context(life.voucher_payload(200), voucher_state_max_age=MAX_AGE)
        await verification.validate_credential_payload(context)
        assert reads(life) == before
        await verification.validate_credential_payload(life.context(life.voucher_payload(200)))
        assert reads(life) == before + 1

    async def test_concurrent_vouchers_never_lose_the_highest(self, life: Lifecycle) -> None:
        await life.open(100)
        amounts = list(range(200, 2_000, 100))
        results = await asyncio.gather(
            *(life.accept(life.voucher_payload(a), voucher_state_max_age=MAX_AGE) for a in amounts),
            return_exceptions=True,
        )
        assert all(
            not isinstance(r, Exception) or isinstance(r, VerificationFailedError) for r in results
        )
        assert (await life.channel()).highest_voucher_amount == amounts[-1]


class TestChargeAmount:
    @pytest.mark.parametrize("max_age", [0, MAX_AGE])
    async def test_charges_in_the_accepting_update(self, life: Lifecycle, max_age: int) -> None:
        await life.open(100)
        charged: list[ChannelState] = []
        receipt = await life.accept(
            life.voucher_payload(250),
            voucher_state_max_age=max_age,
            charge_amount=100,
            on_charged=charged.append,
        )
        assert (receipt.accepted_cumulative, receipt.spent, receipt.units) == ("250", "100", 1)
        assert [c.spent for c in charged] == [100]
        # A resent voucher pays for another request while its balance covers it.
        receipt = await life.accept(
            life.voucher_payload(250), voucher_state_max_age=max_age, charge_amount=100
        )
        assert receipt.spent == "200"
        # The voucher is accepted, but a charge it cannot cover is refused.
        with pytest.raises(InsufficientBalanceError, match="requested 100, available 50"):
            await life.accept(
                life.voucher_payload(250), voucher_state_max_age=max_age, charge_amount=100
            )
        with pytest.raises(InsufficientBalanceError, match="available 70"):
            await life.accept(
                life.voucher_payload(270), voucher_state_max_age=max_age, charge_amount=100
            )
        channel = await life.channel()
        assert (channel.highest_voucher_amount, channel.spent) == (270, 200)

    def test_should_charge_voucher_on_acceptance(self) -> None:
        get = RequestProbe(method="GET", headers=httpx.Headers())
        post = RequestProbe(method="POST", headers=httpx.Headers())
        charge = settlement.should_charge_voucher_on_acceptance
        assert charge(request=get, payload_action="voucher", unit_type="request")
        assert not charge(request=post, payload_action="voucher", unit_type="request")
        assert not charge(request=get, payload_action="open", unit_type="request")
        assert not charge(request=get, payload_action="voucher", unit_type="token")
        assert not charge(request=None, payload_action="voucher", unit_type="request")


class TestThroughTheSessionMethod:
    async def test_charge_on_acceptance_charges_content_once(self, life: Lifecycle) -> None:
        await opened(life, 100, spent=100, units=1)
        handler = handler_for(life, charge_on_acceptance=True, voucher_state_max_age=MAX_AGE)
        result = await pay(handler, life.voucher_payload(200))
        assert isinstance(result, PaymentVerified), result
        receipt = decode_header(result.receipt.to_payment_receipt())
        assert (receipt["spent"], receipt["units"]) == ("200", 2)
        channel = await life.channel()
        assert (channel.spent, channel.units) == (200, 2)
        # A management voucher is accepted without a charge.
        result = await pay(handler, life.voucher_payload(300), method="POST")
        assert isinstance(result, PaymentVerified) and result.response is not None
        assert (await life.channel()).spent == 200
        # A voucher that cannot pay is refused.
        result = await pay(
            handler_for(life, amount="0.0005", charge_on_acceptance=True),
            life.voucher_payload(400),
        )
        assert isinstance(result, PaymentRequired)
        assert (await life.channel()).highest_voucher_amount == 400

    async def test_charge_on_acceptance_settles_on_schedule(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await opened(life, 100, spent=100, units=1)

        async def settled(*args: Any, **kwargs: Any) -> str:
            return "0xdef"

        monkeypatch.setattr(settlement, "settle", settled)
        handler = handler_for(
            life, charge_on_acceptance=True, settlement_schedule=SettlementSchedule(units=2)
        )
        result = await pay(handler, life.voucher_payload(200))
        assert isinstance(result, PaymentVerified)
        assert decode_header(result.receipt.to_payment_receipt())["txHash"] == "0xdef"
        result = await pay(handler, life.voucher_payload(300))
        assert isinstance(result, PaymentVerified)
        assert (await life.channel()).spent == 300

    async def test_opens_are_still_charged_after_acceptance(self, life: Lifecycle) -> None:
        handler = handler_for(life, charge_on_acceptance=True)
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        result = await pay(handler, life.open_payload(100))
        assert isinstance(result, PaymentVerified), result
        assert (await life.channel()).spent == 100

    async def test_voucher_state_max_age_reaches_the_method(self, life: Lifecycle) -> None:
        await opened(life, 100, spent=100, units=1)
        handler = handler_for(life, voucher_state_max_age=MAX_AGE)
        before = reads(life)
        for amount in (200, 300):
            assert isinstance(await pay(handler, life.voucher_payload(amount)), PaymentVerified)
        await settle_background()
        # The method's own cache was never filled, so the first voucher refreshed it once.
        assert reads(life) == before + 1
        assert (await life.channel()).spent == 300
