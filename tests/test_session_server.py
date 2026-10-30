"""Session server: verification, settlement, request state, the channel store and the method.

Ports mppx server/CredentialVerification.test.ts, Settlement.test.ts, RequestState.test.ts and
Session.test.ts. Channels run through the real verification and chain code against a fake node
(tests/session_helpers.py).
"""

from __future__ import annotations

import asyncio
import base64
import gc
import importlib
import json
import logging
import weakref
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from mpp.errors import BadRequestError, VerificationFailedError
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._protocol import (
    ESCROW_ADDRESS,
    ZERO_ADDRESS,
    ChannelDescriptor,
    ClosePayload,
    OpenPayload,
    SessionReceipt,
    SignedVoucher,
    TopUpPayload,
    VoucherPayload,
)
from mpp.methods.tempo.session.server import _request_state as request_state
from mpp.methods.tempo.session.server import _settlement as settlement
from mpp.methods.tempo.session.server import _store as store_module
from mpp.methods.tempo.session.server import _verification as verification
from mpp.methods.tempo.session.server import charge, credit
from mpp.methods.tempo.session.server._schedule import (
    ResolvedSettlementSchedule,
    SettlementSchedule,
    claim_scheduled_settlement,
    mark_settlement_complete,
    release_scheduled_settlement,
    renew_scheduled_settlement,
    resolve_settlement_progress,
)
from mpp.methods.tempo.session.server._store import (
    AmountExceedsDepositError,
    ChannelClosedError,
    ChannelNotFoundError,
    ChannelState,
    DeltaTooSmallError,
    IdempotencyKeyConflictError,
    InsufficientBalanceError,
    InvalidSignatureError,
    PendingSettlement,
    RetainedVoucher,
    StoreChannelStore,
    check_atomic_update,
    from_store,
    resolve_settleable_voucher,
)
from mpp.server import Mpp, PaymentRequired, PaymentVerified, Request, Response
from mpp.store import MemoryStore
from tests.session_helpers import (
    SOURCE,
    Lifecycle,
    authorize,
    challenge_for,
    closed_log,
    make_challenge,
    settled_log,
    sign,
)
from tests.test_session_chain import (
    CHAIN_ID,
    CURRENCY,
    DEPOSIT,
    OTHER_TOKEN,
    PAYEE,
    PAYER,
    RPC,
    SPONSOR,
    fail,
    opened_log,
    top_up_log,
)

# The package exports the session() factory under the module's name.
session = importlib.import_module("mpp.methods.tempo.session.server._session")

DESCRIPTOR = ChannelDescriptor(
    payer=PAYER.address,
    payee=PAYEE.address,
    operator=ZERO_ADDRESS,
    token=CURRENCY,
    salt="0x" + "01" * 32,
    authorized_signer=ZERO_ADDRESS,
    expiring_nonce_hash="0x" + "ab" * 32,
)
CHANNEL_ID = compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID)


def bare_channel(**overrides: Any) -> ChannelState:
    fields: dict[str, Any] = {
        "channel_id": CHANNEL_ID,
        "authorized_signer": PAYER.address,
        "chain_id": CHAIN_ID,
        "escrow_contract": ESCROW_ADDRESS,
        "payer": PAYER.address,
        "payee": PAYEE.address,
        "token": CURRENCY,
        "deposit": 1_000,
        "settled_on_chain": 0,
        "highest_voucher_amount": 0,
        "highest_voucher": None,
        "spent": 0,
        "units": 0,
        "close_requested_at": 0,
        "finalized": False,
        "created_at": "t",
    }
    fields.update(overrides)
    return ChannelState(**fields)


@pytest.fixture
async def life() -> Lifecycle:
    return await Lifecycle().build()


async def opened(life: Lifecycle, amount: int = 300, **fields: Any) -> Lifecycle:
    await life.open(amount)
    if fields:
        await life.update(**fields)
    return life


# --------------------------------------------------------------------------------------------
# Open, voucher, top-up and close through the chain layer (CredentialVerification.test.ts)
# --------------------------------------------------------------------------------------------


class TestLifecycle:
    async def test_open_voucher_top_up_and_close(self, life: Lifecycle) -> None:
        settlements: list[settlement.SessionSettlementContext] = []
        validation = await verification.validate_credential_payload(
            life.context(life.open_payload())
        )
        assert (validation.action, validation.channel_id) == ("open", life.channel_id)
        # Validation simulates the open without sending it.
        assert not life.rpc.sent and life.rpc.methods("eth_call")

        opened = await life.open()
        assert opened.tx_hash == "0x" + f"{1:064x}"
        assert opened.accepted_cumulative == "100" and life.last_verified[life.channel_id] > 0
        channel = await life.channel()
        assert channel.deposit == DEPOSIT and channel.descriptor == life.descriptor

        receipt = await life.accept(life.voucher_payload(300))
        assert receipt.accepted_cumulative == "300" and receipt.tx_hash is None
        assert (receipt.channel_id, receipt.challenge_id) == (life.channel_id, "challenge-1")
        assert (await life.channel()).on_chain_verified_at is not None

        top_up = await life.top_up_payload()
        await verification.validate_credential_payload(life.context(top_up))
        life.rpc.logs = [top_up_log(life.descriptor, life.channel_id, 500, DEPOSIT + 500)]
        life.rpc.states[life.channel_id] = (0, DEPOSIT + 500, 0)
        topped = await life.accept(top_up)
        assert topped.accepted_cumulative == "300" and topped.tx_hash is not None
        assert (await life.channel()).deposit == DEPOSIT + 500

        await life.update(spent=250)
        close = life.close_payload(300)
        await verification.validate_credential_payload(life.context(close))
        life.rpc.logs = [closed_log(life.descriptor, life.channel_id, 250, DEPOSIT + 250)]
        closed = await life.accept(close, on_session_settlement=settlements.append)
        assert closed.accepted_cumulative == "300" and closed.spent == "250"
        channel = await life.channel()
        assert channel.finalized and channel.settled_on_chain == 250
        assert [(s.trigger, s.amount, s.delta) for s in settlements] == [("close", 250, 250)]

    async def test_open_rejects_a_mismatched_authorized_signer(self, life: Lifecycle) -> None:
        payload = life.open_payload(authorizedSigner=PAYEE.address)
        with pytest.raises(VerificationFailedError, match="authorizedSigner"):
            await verification.validate_credential_payload(life.context(payload))
        with pytest.raises(VerificationFailedError, match="authorizedSigner"):
            await life.accept(payload)
        matching = life.open_payload(authorizedSigner=PAYER.address)
        await verification.validate_credential_payload(life.context(matching))

    @pytest.mark.parametrize(
        ("amount", "signer", "challenge_amount", "error", "match"),
        [
            (DEPOSIT + 1, PAYER, "100", AmountExceedsDepositError, "open deposit"),
            (100, PAYEE, "100", InvalidSignatureError, "voucher signature"),
            (100, PAYER, str(DEPOSIT + 1), VerificationFailedError, "less than request"),
            (50, PAYER, "100", VerificationFailedError, "voucher amount is less"),
        ],
    )
    async def test_open_voucher_must_cover_and_be_signed(
        self,
        life: Lifecycle,
        amount: int,
        signer: Any,
        challenge_amount: str,
        error: type[Exception],
        match: str,
    ) -> None:
        payload = life.open_payload(amount, signature=sign(life.channel_id, amount, signer))
        context = life.context(payload, challenge=make_challenge(challenge_amount))
        with pytest.raises(error, match=match):
            await verification.validate_credential_payload(context)
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        with pytest.raises(error, match=match):
            await verification.broadcast_credential_payload(context)
        # The voucher is checked before the open is sent.
        assert not life.rpc.sent
        assert await life.store.get_channel(life.channel_id) is None

    async def test_open_replay_must_advance_for_content(self, life: Lifecycle) -> None:
        await life.open(300)
        with pytest.raises(DeltaTooSmallError):
            await life.open(300, require_voucher_advance=True)
        # A higher replayed open keeps the superseded voucher for settlement.
        await life.open(500)
        channel = await life.channel()
        assert channel.highest_voucher_amount == 500
        assert [v.cumulative_amount for v in channel.retained_vouchers or ()] == [300]

    async def test_sponsored_open_advertises_both_fee_tokens(self) -> None:
        life = await Lifecycle().build(fee_payer=True, fee_token=OTHER_TOKEN)
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        receipt = await life.accept(life.open_payload(), fee_payer=SPONSOR, fee_token=OTHER_TOKEN)
        assert receipt.tx_hash is not None
        assert life.rpc.sent[0].startswith("0x76")

    async def test_top_up_needs_an_open_channel_on_chain(self, life: Lifecycle) -> None:
        await life.open()
        top_up = await life.top_up_payload()
        life.rpc.states[life.channel_id] = (0, DEPOSIT, 1_700_000_000)
        with pytest.raises(ChannelClosedError, match="pending close"):
            await verification.validate_credential_payload(life.context(top_up))
        life.rpc.states[life.channel_id] = (0, 0, 0)
        with pytest.raises(ChannelNotFoundError, match="not funded"):
            await verification.validate_credential_payload(life.context(top_up))


class TestVoucher:
    @pytest.mark.parametrize(
        ("case", "error", "match"),
        [
            ({"opened": 500, "amount": 400}, VerificationFailedError, "strictly greater"),
            ({"amount": DEPOSIT + 1}, AmountExceedsDepositError, "exceeds"),
            ({"state": (500, DEPOSIT, 0), "amount": 500}, VerificationFailedError, "settled"),
            ({"amount": 149, "options": {"min_voucher_delta": 50}}, DeltaTooSmallError, "50"),
            ({"signer": PAYEE}, InvalidSignatureError, "signature"),
            (
                {"opened": 200, "amount": 200, "options": {"require_voucher_advance": True}},
                DeltaTooSmallError,
                None,
            ),
            ({"descriptor": True}, VerificationFailedError, "does not match channelId"),
            ({"fields": {"finalized": True}}, ChannelClosedError, "finalized"),
            ({"fields": {"backend": "contract"}}, VerificationFailedError, "not precompile"),
        ],
    )
    async def test_rejects(
        self, life: Lifecycle, case: dict[str, Any], error: type[Exception], match: str | None
    ) -> None:
        await opened(life, case.get("opened", 100), **case.get("fields", {}))
        if "state" in case:
            life.rpc.states[life.channel_id] = case["state"]
        amount = case.get("amount", 300)
        overrides: dict[str, Any] = {}
        if "signer" in case:
            overrides["signature"] = sign(life.channel_id, amount, case["signer"])
        if "descriptor" in case:
            other = replace(life.descriptor, salt="0x" + "02" * 32)
            overrides["descriptor"] = other.to_wire()
        payload = life.voucher_payload(amount, **overrides)
        # Validation reads the chain again rather than trusting the open's read.
        context = life.context(payload, last_on_chain_verified={}, **case.get("options", {}))
        if match is not None:  # A content request's advance is checked on acceptance only.
            with pytest.raises(error, match=match):
                await verification.validate_credential_payload(context)
        with pytest.raises(error, match=match):
            await verification.broadcast_credential_payload(context)

    async def test_accepts_a_resent_voucher_and_the_minimum_delta(self, life: Lifecycle) -> None:
        await life.open(200)
        # A management request may resend the accepted voucher: nothing changes.
        assert (await life.accept(life.voucher_payload(200))).accepted_cumulative == "200"
        receipt = await life.accept(life.voucher_payload(250), min_voucher_delta=50)
        assert receipt.accepted_cumulative == "250"

    async def test_expired_local_close_marker_is_cleared_by_a_voucher(
        self, life: Lifecycle
    ) -> None:
        await opened(life, 100, close_requested_at=1_000)
        assert (await life.accept(life.voucher_payload(200))).accepted_cumulative == "200"
        assert (await life.channel()).close_requested_at == 0

    async def test_pending_close_on_chain_settles_the_spend_and_is_recorded(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await opened(life, 100, spent=100)
        settled: list[str] = []

        async def fake_settle(*args: Any, **kwargs: Any) -> str:
            settled.append("settle")
            return "0x" + "ee" * 32

        monkeypatch.setattr(settlement, "settle", fake_settle)
        life.rpc.states[life.channel_id] = (0, DEPOSIT, 1_700_000_000)
        with pytest.raises(ChannelClosedError, match="pending close"):
            await life.accept(life.voucher_payload(300))
        assert (await life.channel()).close_requested_at == 1_700_000_000
        # The accepted spend is settled while the payee still can.
        assert settled == ["settle"]
        with pytest.raises(ChannelClosedError):
            await settlement.charge_session_channel(life.store, life.channel_id, 1)
        # Without a deposit left nothing is settled.
        life.rpc.states[life.channel_id] = (40, 0, 1_700_000_000)
        with pytest.raises(ChannelClosedError, match="pending close"):
            await life.accept(life.voucher_payload(300))
        assert settled == ["settle"] and (await life.channel()).settled_on_chain == 40

    async def test_validation_caches_chain_state_and_may_allow_a_pending_close(
        self, life: Lifecycle
    ) -> None:
        await life.open()
        reads = len(life.rpc.methods("eth_call"))
        for amount in (200, 300):
            await verification.validate_credential_payload(
                life.context(life.voucher_payload(amount))
            )
        # The open's read is still fresh.
        assert len(life.rpc.methods("eth_call")) == reads
        # Acceptance always reads chain state first.
        await life.accept(life.voucher_payload(300))
        assert len(life.rpc.methods("eth_call")) == reads + 1
        life.rpc.states[life.channel_id] = (0, DEPOSIT, 5)
        payload = life.voucher_payload(400)
        with pytest.raises(ChannelClosedError):
            await verification.validate_credential_payload(
                life.context(payload, last_on_chain_verified={})
            )
        result = await verification.validate_credential_payload(
            life.context(payload, last_on_chain_verified={}, allow_pending_close=True)
        )
        assert result.action == "voucher"

    async def test_concurrent_vouchers_never_lose_the_highest(self, life: Lifecycle) -> None:
        await life.open()
        amounts = list(range(200, 2_000, 100))
        results = await asyncio.gather(
            *(life.accept(life.voucher_payload(a)) for a in amounts), return_exceptions=True
        )
        assert all(
            not isinstance(r, Exception) or isinstance(r, VerificationFailedError) for r in results
        )
        assert (await life.channel()).highest_voucher_amount == amounts[-1]

    async def test_store_errors_win_over_the_chain_read(self, life: Lifecycle) -> None:
        with pytest.raises(ChannelNotFoundError):
            await life.accept(life.voucher_payload(200))

    async def test_voucher_for_a_vanished_channel(self, life: Lifecycle) -> None:
        await life.open()
        channel = await life.channel()
        await life.store.update_channel(life.channel_id, lambda c: None)
        with pytest.raises(ChannelNotFoundError):
            await verification.verify_and_accept_voucher(
                store=life.store,
                challenge_id="c",
                channel=channel,
                voucher=SignedVoucher(
                    channel_id=life.channel_id,
                    cumulative_amount=200,
                    signature=sign(life.channel_id, 200),
                ),
                channel_state=chain.ChannelState(0, DEPOSIT, 0),
                chain_id=CHAIN_ID,
                escrow=ESCROW_ADDRESS,
                min_voucher_delta=0,
            )

    async def test_amounts_beyond_uint96_are_verification_failures(self, life: Lifecycle) -> None:
        await life.open()
        payload = life.voucher_payload(200, cumulativeAmount=str(1 << 96))
        with pytest.raises(VerificationFailedError, match="uint96"):
            await verification.validate_credential_payload(life.context(payload))
        close = life.close_payload(200).model_copy(update={"cumulative_amount": str(1 << 96)})
        with pytest.raises(VerificationFailedError, match="uint96"):
            await verification.validate_credential_payload(life.context(close))

    async def test_a_payload_without_descriptor_is_refused(self, life: Lifecycle) -> None:
        payload = life.voucher_payload(200).model_copy(update={"descriptor": None})
        with pytest.raises(VerificationFailedError, match="descriptor required"):
            await verification.validate_credential_payload(life.context(payload))


class TestClose:
    async def test_rejects_a_finalized_channel(self, life: Lifecycle) -> None:
        await opened(life, finalized=True)
        with pytest.raises(ChannelClosedError, match="already finalized"):
            await verification.validate_credential_payload(life.context(life.close_payload(300)))

    @pytest.mark.parametrize(
        ("state", "error", "match"),
        [
            ((0, DEPOSIT, 1_700_000_000), ChannelClosedError, "pending close"),
            ((0, 0, 0), ChannelClosedError, "deposit is zero"),
            ((400, DEPOSIT, 0), VerificationFailedError, "on-chain settled"),
            ((0, 200, 0), AmountExceedsDepositError, "exceeds on-chain deposit"),
        ],
    )
    async def test_checks_on_chain_state(
        self, life: Lifecycle, state: tuple[int, int, int], error: type[Exception], match: str
    ) -> None:
        await opened(life, spent=250)
        life.rpc.states[life.channel_id] = state
        with pytest.raises(error, match=match):
            await verification.validate_credential_payload(life.context(life.close_payload(300)))

    async def test_rejects_bad_signatures_amounts_and_senders(self, life: Lifecycle) -> None:
        await opened(life, spent=250)
        close = life.close_payload(300).model_copy(
            update={"signature": sign(life.channel_id, 300, PAYEE)}
        )
        with pytest.raises(InvalidSignatureError, match="invalid voucher signature"):
            await verification.validate_credential_payload(life.context(close))
        with pytest.raises(VerificationFailedError, match="spent"):
            await life.accept(life.close_payload(200))
        with pytest.raises(InvalidSignatureError, match="close authorization"):
            await life.accept(life.close_payload(300, close_signer=SPONSOR))
        with pytest.raises(BadRequestError, match="not the channel payee"):
            await life.accept(life.close_payload(300), account=SPONSOR)

    async def test_capture_is_at_least_settled(self, life: Lifecycle) -> None:
        await opened(life, spent=100, settled_on_chain=200)
        life.rpc.states[life.channel_id] = (200, DEPOSIT, 0)
        # The event would contradict a capture below 200.
        life.rpc.logs = [closed_log(life.descriptor, life.channel_id, 200, DEPOSIT - 200)]
        await life.accept(life.close_payload(300))
        assert (await life.channel()).settled_on_chain == 200

    async def test_rejects_close_amounts_the_event_contradicts(self, life: Lifecycle) -> None:
        await opened(life, spent=250)
        life.rpc.logs = [closed_log(life.descriptor, life.channel_id, 260, 0)]
        with pytest.raises(VerificationFailedError, match="ChannelClosed amounts"):
            await life.accept(life.close_payload(300))

    async def test_reverted_close_clears_its_pending_marker(self, life: Lifecycle) -> None:
        await opened(life, spent=250)
        life.rpc.receipt_status = "0x0"
        failures: list[settlement.SessionSettlementFailureContext] = []
        with pytest.raises(VerificationFailedError, match="reverted"):
            await life.accept(
                life.close_payload(300), on_session_settlement_failure=failures.append
            )
        assert (await life.channel()).close_requested_at == 0
        assert [f.trigger for f in failures] == ["close"]

    async def test_unknown_outcome_after_send_keeps_the_pending_marker(
        self, life: Lifecycle
    ) -> None:
        await opened(life, spent=250)
        life.rpc.overrides["eth_getTransactionReceipt"] = fail("node lost")
        with pytest.raises(Exception, match="node lost"):
            await life.accept(life.close_payload(300))
        # The close may still land: charges stop until it expires and is reconciled.
        assert (await life.channel()).close_requested_at != 0
        with pytest.raises(ChannelClosedError):
            await settlement.charge_session_channel(life.store, life.channel_id, 1)

    async def test_close_that_would_revert_is_never_sent(self, life: Lifecycle) -> None:
        # A withdrawn channel (deposit 0, nothing spent) passes validation with a zero close,
        # as in mppx; its gas estimate fails, so like viem nothing is broadcast.
        await opened(life)
        life.rpc.states[life.channel_id] = (0, 0, 0)
        life.rpc.overrides["eth_estimateGas"] = fail("execution reverted")
        sent = len(life.rpc.sent)
        for _ in range(2):
            with pytest.raises(RuntimeError, match="execution reverted"):
                await life.accept(life.close_payload(0))
            assert (await life.channel()).close_requested_at == 0
        assert len(life.rpc.sent) == sent

    async def test_close_without_a_caller_client(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await opened(life, spent=250)
        real_client = httpx.AsyncClient
        transport = httpx.MockTransport(life.rpc._handle)
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(transport=transport))
        life.rpc.logs = [closed_log(life.descriptor, life.channel_id, 250, DEPOSIT - 250)]
        receipt = await life.accept(life.close_payload(300), http_client=None)
        assert receipt.tx_hash is not None and (await life.channel()).finalized


# --------------------------------------------------------------------------------------------
# Payload and descriptor checks
# --------------------------------------------------------------------------------------------


class TestDescriptorAndStateChecks:
    def test_assert_same_descriptor(self) -> None:
        verification.assert_same_descriptor(
            DESCRIPTOR, replace(DESCRIPTOR, payer=PAYER.address.lower())
        )
        with pytest.raises(VerificationFailedError, match="does not match stored"):
            verification.assert_same_descriptor(
                DESCRIPTOR, replace(DESCRIPTOR, salt="0x" + "02" * 32)
            )

    @pytest.mark.parametrize(
        ("recipient", "currency", "operator", "match"),
        [
            (PAYER.address, CURRENCY, None, "payee does not match"),
            (PAYEE.address, OTHER_TOKEN, None, "token does not match"),
            (PAYEE.address, CURRENCY, PAYEE.address, "operator does not match"),
        ],
    )
    def test_validate_channel_descriptor(
        self, recipient: str, currency: str, operator: str | None, match: str
    ) -> None:
        verification.validate_channel_descriptor(
            DESCRIPTOR, CHANNEL_ID, CHAIN_ID, ESCROW_ADDRESS, PAYEE.address, CURRENCY, ZERO_ADDRESS
        )
        with pytest.raises(VerificationFailedError, match=match):
            verification.validate_channel_descriptor(
                DESCRIPTOR, CHANNEL_ID, CHAIN_ID, ESCROW_ADDRESS, recipient, currency, operator
            )

    def test_validate_channel_state(self) -> None:
        verification.validate_channel_state(chain.ChannelState(10, 100, 0), 90)
        with pytest.raises(InsufficientBalanceError):
            verification.validate_channel_state(chain.ChannelState(10, 100, 0), 91)

    @pytest.mark.parametrize(
        ("source", "match"),
        [
            (f"did:pkh:eip155:{CHAIN_ID}:0x12", "invalid credential source"),
            (f"did:pkh:eip155:{CHAIN_ID}:{PAYEE.address}", "does not match channel"),
            (None, "does not match channel"),
        ],
    )
    def test_credential_source_must_be_the_payer(self, source: str | None, match: str) -> None:
        channel = bare_channel(deposit=1)
        verification.assert_credential_source_can_spend(
            chain_id=CHAIN_ID, channel=channel, source=SOURCE.lower()
        )
        with pytest.raises(VerificationFailedError, match=match):
            verification.assert_credential_source_can_spend(
                chain_id=CHAIN_ID, channel=channel, source=source
            )

    def test_allowed_fee_tokens(self) -> None:
        assert verification._allowed_fee_tokens(CURRENCY, None) == [CURRENCY]
        assert verification._allowed_fee_tokens(CURRENCY, CURRENCY.lower()) == [CURRENCY]
        assert verification._allowed_fee_tokens(CURRENCY, OTHER_TOKEN) == [OTHER_TOKEN, CURRENCY]


def wire(action: str, **fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "action": action,
        "channelId": CHANNEL_ID.upper().replace("0X", "0x"),
        "descriptor": DESCRIPTOR.to_wire(),
        "cumulativeAmount": "10",
        "signature": "0x01",
        "closeSignature": "0x02",
        "transaction": "0x76",
        "type": "transaction",
        "additionalDeposit": "5",
    }
    base.update(fields)
    return base


class TestRequirePayload:
    @pytest.mark.parametrize(
        ("payload", "kind"),
        [
            (wire("open", authorizedSigner=PAYER.address), OpenPayload),
            (wire("topUp"), TopUpPayload),
            (wire("voucher"), VoucherPayload),
            (wire("close"), ClosePayload),
        ],
    )
    def test_accepts_each_action(self, payload: dict[str, Any], kind: type) -> None:
        parsed = verification.require_session_credential_payload(payload)
        assert isinstance(parsed, kind)
        assert parsed.channel_id == CHANNEL_ID.lower()
        # The parsed model is accepted too.
        assert verification.require_session_credential_payload(parsed) == parsed

    @pytest.mark.parametrize(
        ("payload", "match"),
        [
            ("voucher", "invalid session credential payload"),
            (wire("settle"), "action"),
            (wire("open", type="hash"), "transaction type"),
            (wire("topUp", type="hash"), "transaction type"),
            (wire("open", authorizedSigner="0x12"), "authorizedSigner"),
            (wire("voucher", descriptor=None), "descriptor required"),
            (wire("voucher", descriptor="payer"), "invalid session credential payload"),
            (wire("voucher", descriptor={**DESCRIPTOR.to_wire(), "salt": "0x01"}), "salt"),
            (wire("voucher", cumulativeAmount="1.5"), "cumulativeAmount"),
            (wire("close", closeSignature="nope"), "closeSignature"),
        ],
    )
    def test_rejects(self, payload: Any, match: str) -> None:
        with pytest.raises(VerificationFailedError, match=match):
            verification.require_session_credential_payload(payload)


# --------------------------------------------------------------------------------------------
# Request state (RequestState.test.ts)
# --------------------------------------------------------------------------------------------


class TestRequestState:
    @pytest.mark.parametrize(
        ("method", "url", "headers", "body", "content"),
        [
            ("GET", "http://x/paid", {}, None, True),
            ("HEAD", "http://x/paid", {}, None, False),
            ("POST", "http://x/paid", {}, None, False),
            ("POST", "http://x/paid", {"content-length": "0"}, None, False),
            ("POST", "http://x/paid?q=1", {}, None, True),
            ("POST", "http://x/paid", {"content-length": "12"}, None, True),
            ("POST", "http://x/paid", {"transfer-encoding": "chunked"}, None, True),
            ("POST", "http://x/paid", {}, b"{}", True),
        ],
    )
    def test_content_request_classifier(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None, content: bool
    ) -> None:
        probe = request_state.capture_request_probe(
            Request(method, url, headers=headers, body=body)
        )
        assert request_state.is_session_content_request(probe) is content
        respond = request_state.respond_to_session_credential
        assert (respond(payload_action="voucher", request=probe) is None) is content
        top_up = respond(payload_action="topUp", request=probe)
        assert top_up is not None and top_up.status == 204

    @pytest.mark.parametrize(
        ("headers", "has_body", "expected"),
        [
            ({"content-length": "5"}, False, True),
            ({"transfer-encoding": "chunked"}, False, True),
            ({"content-length": "0", "transfer-encoding": "chunked"}, False, True),
            ({}, True, True),
            ({}, None, False),
        ],
    )
    def test_has_captured_request_body(
        self, headers: dict[str, str], has_body: bool | None, expected: bool
    ) -> None:
        probe = request_state.RequestProbe("POST", httpx.Headers(headers), has_body)
        assert request_state.has_captured_request_body(probe) is expected

    def test_respond_to_session_credential(self) -> None:
        respond = request_state.respond_to_session_credential
        with pytest.raises(VerificationFailedError, match="action"):
            respond(payload_action="settle", request=None)
        assert respond(payload_action="open", request=None) is None
        close = respond(payload_action="close", request=None)
        assert close is not None and close.status == 204
        # A bare POST without a URL is management.
        probe = request_state.RequestProbe("POST", httpx.Headers())
        assert not request_state.is_session_content_request(probe)

    def test_fee_payer_resolution(self) -> None:
        resolve = request_state.resolve_request_fee_payer
        assert resolve(default_fee_payer=SPONSOR, request_fee_payer=False) is None
        # A route's own account is kept for verification; the wire advertises it as true.
        assert resolve(default_fee_payer=None, request_fee_payer=SPONSOR) is SPONSOR
        assert resolve(default_fee_payer=None, request_fee_payer=True) is None
        assert resolve(default_fee_payer=SPONSOR) is True
        assert resolve(default_fee_payer=None) is None
        credential = request_state.resolve_credential_fee_payer
        sponsored = {"feePayer": True}
        assert credential(method_details=sponsored, fee_payer=SPONSOR) is SPONSOR
        assert credential(method_details={"feePayer": "true"}, fee_payer=SPONSOR) is None
        assert (
            credential(method_details=sponsored, fee_payer=None, request_fee_payer=PAYEE) is PAYEE
        )
        assert (
            credential(method_details=sponsored, fee_payer=SPONSOR, request_fee_payer=True)
            is SPONSOR
        )
        assert (
            credential(method_details=sponsored, fee_payer=SPONSOR, request_fee_payer=False) is None
        )

    def test_normalize_session_channel_id(self) -> None:
        assert request_state.normalize_session_channel_id(CHANNEL_ID.upper()[2:]) is None
        assert request_state.normalize_session_channel_id(42) is None
        assert request_state.normalize_session_channel_id("0x" + CHANNEL_ID[2:].upper()) == (
            CHANNEL_ID.lower()
        )

    @pytest.mark.parametrize(
        ("request_fields", "match"),
        [
            ({"amount": "1.5"}, "amount"),
            ({"amount": 10}, "amount"),
            ({"currency": "usd"}, "currency"),
            ({"recipient": None}, "recipient"),
        ],
    )
    def test_challenge_payment_fields(self, request_fields: dict[str, Any], match: str) -> None:
        challenge = make_challenge()
        fields = request_state.get_challenge_payment_fields(challenge)
        assert (fields.amount, fields.currency, fields.recipient) == (100, CURRENCY, PAYEE.address)
        broken = replace(challenge, request={**challenge.request, **request_fields})
        with pytest.raises(VerificationFailedError, match=match):
            request_state.get_challenge_payment_fields(broken)

    @pytest.mark.parametrize(
        "change",
        [
            {"chainId": True},
            {"chainId": "1337"},
            {"escrowContract": "0x12"},
            {"feePayer": "yes"},
            {"feeToken": "usd"},
            {"minVoucherDelta": 5},
            {"operator": "0x12"},
            {"sessionProtocol": "v1"},
            {"methodDetails": None},
            {"unitType": 1},
        ],
    )
    def test_method_details_are_checked(self, change: dict[str, Any]) -> None:
        top = {k: v for k, v in change.items() if k in ("methodDetails", "unitType")}
        details = {k: v for k, v in change.items() if k not in top}
        with pytest.raises(VerificationFailedError, match="invalid session request"):
            request_state.read_method_details({**make_challenge(**details).request, **top})

    def test_method_details_are_read(self) -> None:
        details = request_state.read_method_details(
            make_challenge(
                feePayer=True, feeToken=CURRENCY, minVoucherDelta="5", operator=PAYEE.address
            ).request
        )
        assert details == request_state.SessionMethodDetails(
            chain_id=CHAIN_ID,
            escrow_contract=ESCROW_ADDRESS,
            fee_payer=True,
            fee_token=CURRENCY,
            min_voucher_delta="5",
            operator=PAYEE.address,
            session_protocol="v2",
        )

    def test_verification_context_resolves_the_minimum_delta(self) -> None:
        resolve = request_state.resolve_credential_verification_context
        context = resolve(
            challenge=make_challenge(minVoucherDelta="7", feePayer=True),
            decimals=6,
            fee_payer=SPONSOR,
            min_voucher_delta="1",
        )
        assert context.min_voucher_delta == 7 and context.fee_payer is SPONSOR
        fallback = resolve(
            challenge=make_challenge(), decimals=6, fee_payer=SPONSOR, min_voucher_delta="0.01"
        )
        assert fallback.min_voucher_delta == 10_000 and fallback.fee_payer is None
        with pytest.raises(VerificationFailedError, match="invalid session request"):
            resolve(
                challenge=make_challenge(minVoucherDelta="0.5"),
                decimals=6,
                fee_payer=None,
                min_voucher_delta=None,
            )

    def test_payment_request_resolution(self) -> None:
        def resolve(request: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            options: dict[str, Any] = {
                "chain_id": CHAIN_ID,
                "default_fee_payer": None,
                "parameter_escrow_contract": None,
                "fee_token": None,
            }
            options.update(kwargs)
            return request_state.resolve_session_payment_request(request=request, **options)

        resolved = resolve(
            {"amount": "1", "chainId": 4217, "operator": PAYEE.address, "feePayer": False},
            default_fee_payer=SPONSOR,
            fee_token=CURRENCY,
        )
        assert resolved == {
            "amount": "1",
            "chain_id": 4217,
            "escrow_contract": ESCROW_ADDRESS,
            "operator": PAYEE.address,
            "fee_token": CURRENCY,
            "session_protocol": "v2",
            # The opt-out stays off the wire but reaches verification.
            "_fee_payer_disabled": True,
        }
        custom = resolve({"escrowContract": PAYER.address})
        assert custom["escrow_contract"] == PAYER.address and "fee_payer" not in custom
        with pytest.raises(ValueError, match="escrow_contract"):
            resolve({"escrow_contract": "0x12"})
        with pytest.raises(ValueError, match="operator"):
            resolve({"operator": "0x12"})


# --------------------------------------------------------------------------------------------
# Settlement (Settlement.test.ts)
# --------------------------------------------------------------------------------------------


def scheduled(life: Lifecycle, channel: ChannelState, **kwargs: Any) -> Any:
    options: dict[str, Any] = {
        "channel": channel,
        "schedule": ResolvedSettlementSchedule(units=1),
        "store": life.store,
        "account": PAYEE,
        "rpc_url": RPC,
        "http_client": life.rpc.client,
    }
    options.update(kwargs)
    return settlement.maybe_settle_scheduled(**options)


class TestSettle:
    async def _ready(self, life: Lifecycle, *, settled: int | None = 300) -> None:
        await opened(life, spent=300, units=3)
        if settled is not None:
            life.rpc.logs = [settled_log(life.descriptor, life.channel_id, settled, settled)]
            life.rpc.states[life.channel_id] = (settled, DEPOSIT, 0)

    async def test_settles_through_the_chain_and_records_it(self, life: Lifecycle) -> None:
        await self._ready(life)
        events: list[settlement.SessionSettlementContext] = []

        async def on_settlement(context: settlement.SessionSettlementContext) -> None:
            events.append(context)

        tx_hash = await settlement.settle(
            life.raw,
            life.channel_id,
            account=PAYEE,
            rpc_url=RPC,
            http_client=life.rpc.client,
            on_session_settlement=on_settlement,
        )
        assert tx_hash == "0x" + f"{2:064x}"
        channel = await life.channel()
        assert channel.settled_on_chain == 300 and channel.last_settlement_units == 3
        assert channel.last_settlement_spent == 300 and channel.pending_settlement is None
        assert [(e.trigger, e.amount, e.delta) for e in events] == [("settle", 300, 300)]
        # Settlement reads back at the receipt's block.
        assert life.rpc.methods("eth_call")[-1][1] == "0x10"
        with pytest.raises(VerificationFailedError, match="nothing to settle"):
            await settlement.settle(life.raw, life.channel_id, account=PAYEE, rpc_url=RPC)

    async def test_settle_batch(self, life: Lifecycle) -> None:
        await self._ready(life)
        hashes = await settlement.settle_batch(
            life.store, [life.channel_id], account=PAYEE, rpc_url=RPC, http_client=life.rpc.client
        )
        assert len(hashes) == 1

    @pytest.mark.parametrize(
        ("state", "logged", "match"),
        [
            ((300, DEPOSIT, 0), 299, "below voucher amount"),
            ((299, DEPOSIT, 0), 300, "does not match settle receipt"),
            ((300, DEPOSIT, 0), None, "reverted"),
        ],
    )
    async def test_rejects_failed_or_inconsistent_results(
        self, life: Lifecycle, state: tuple[int, int, int], logged: int | None, match: str
    ) -> None:
        await self._ready(life, settled=logged)
        life.rpc.states[life.channel_id] = state
        if logged is None:
            life.rpc.receipt_status = "0x0"
        with pytest.raises(VerificationFailedError, match=match):
            await settlement.settle(
                life.store, life.channel_id, account=PAYEE, rpc_url=RPC, http_client=life.rpc.client
            )
        if logged is None:  # A reverted settlement releases its credit floor.
            assert (await life.channel()).pending_settlement is None

    async def test_requires_a_settleable_precompile_channel(self, life: Lifecycle) -> None:
        kwargs: dict[str, Any] = {"account": PAYEE, "rpc_url": RPC}
        with pytest.raises(ChannelNotFoundError):
            await settlement.settle(life.store, life.channel_id, **kwargs)
        await self._ready(life)
        await life.update(highest_voucher=None)
        with pytest.raises(VerificationFailedError, match="no voucher to settle"):
            await settlement.settle(life.store, life.channel_id, **kwargs)
        await life.update(backend="contract")
        with pytest.raises(VerificationFailedError, match="not precompile-backed"):
            await settlement.settle(life.store, life.channel_id, **kwargs)

    async def test_settle_replaces_an_expired_credit_floor(self, life: Lifecycle) -> None:
        await self._ready(life)
        await life.update(pending_settlement=PendingSettlement(amount=900, expires_at=1))
        await settlement.settle(
            life.store, life.channel_id, account=PAYEE, rpc_url=RPC, http_client=life.rpc.client
        )
        # The expired floor was dropped rather than kept at 900.
        assert (await life.channel()).pending_settlement is None

    async def test_checkpoint_failure_still_reports_the_settlement(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life)
        real = StoreChannelStore.update_channel
        calls: list[int] = []

        async def flaky(self: StoreChannelStore, channel_id: str, fn: Any) -> Any:
            calls.append(1)
            if len(calls) == 2:  # the record after the transaction confirmed
                raise RuntimeError("store down")
            return await real(self, channel_id, fn)

        monkeypatch.setattr(StoreChannelStore, "update_channel", flaky)
        events: list[settlement.SessionSettlementContext] = []
        with pytest.raises(settlement.SettlementCheckpointError) as raised:
            await settlement.settle(
                life.store,
                life.channel_id,
                account=PAYEE,
                rpc_url=RPC,
                http_client=life.rpc.client,
                on_session_settlement=events.append,
            )
        assert raised.value.tx_hash.startswith("0x")
        assert len(events) == 1

    async def test_scheduled_settlement_runs_once_under_lease(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life)
        channel = await life.channel()
        real = chain.settle_on_chain

        async def slow(*args: Any, **kwargs: Any) -> str:
            await asyncio.sleep(0.05)
            return await real(*args, **kwargs)

        monkeypatch.setattr(chain, "settle_on_chain", slow)
        schedule = ResolvedSettlementSchedule(units=2)
        results = await asyncio.gather(
            *(scheduled(life, channel, schedule=schedule) for _ in "abc")
        )
        assert sorted(r is not None for r in results) == [False, False, True]
        assert len(life.rpc.sent) == 2  # the open and one settlement
        done = await life.channel()
        assert done.scheduled_settlement_lease is None and done.last_settlement_at is not None
        # Not due again until two more units are paid.
        assert await scheduled(life, done, schedule=schedule) is None

    async def test_scheduled_failures_are_reported_and_release_the_lease(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life, settled=None)

        async def unreachable(*args: Any, **kwargs: Any) -> str:
            raise httpx.ConnectError("down")

        monkeypatch.setattr(chain, "settle_on_chain", unreachable)
        failures: list[Any] = []
        with pytest.raises(Exception) as raised:
            await scheduled(
                life, await life.channel(), on_session_settlement_failure=failures.append
            )
        assert [f.trigger for f in failures] == ["scheduled"]
        # Transport failures keep the charged request served; the next settlement retries.
        assert settlement.ignore_retryable_settlement_failure(raised.value) is None
        with pytest.raises(BadRequestError):
            settlement.ignore_retryable_settlement_failure(BadRequestError("nope"))
        assert (await life.channel()).scheduled_settlement_lease is None

    async def test_scheduled_checkpoint_failure_returns_the_hash(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life, settled=None)

        async def confirmed_unrecorded(*args: Any, **kwargs: Any) -> str:
            raise settlement.SettlementCheckpointError(tx_hash="0xabc", cause=RuntimeError())

        monkeypatch.setattr(settlement, "settle", confirmed_unrecorded)
        failures: list[settlement.SessionSettlementFailureContext] = []
        channel = await life.channel()
        tx_hash = await scheduled(life, channel, on_session_settlement_failure=failures.append)
        assert tx_hash == "0xabc" and len(failures) == 1
        assert (await life.channel()).scheduled_settlement_lease is None

    async def test_scheduled_settlement_needs_an_account(self, life: Lifecycle) -> None:
        await self._ready(life, settled=None)
        with pytest.raises(ValueError, match="no account available"):
            await scheduled(life, await life.channel(), account=None)

    async def test_scheduled_lease_failure_is_retryable(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life, settled=None)

        async def broken(**kwargs: Any) -> str:
            raise RuntimeError("store down")

        monkeypatch.setattr(settlement, "claim_scheduled_settlement", broken)
        failures: list[settlement.SessionSettlementFailureContext] = []

        def boom(context: settlement.SessionSettlementFailureContext) -> None:
            failures.append(context)
            raise RuntimeError("observer errors are swallowed")

        with pytest.raises(settlement.SettlementLeaseError) as raised:
            await scheduled(life, await life.channel(), on_session_settlement_failure=boom)
        assert len(failures) == 1
        assert settlement.ignore_retryable_settlement_failure(raised.value) is None

    async def test_scheduled_settlement_survives_a_failed_completion_mark(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life, settled=None)

        async def settled(*args: Any, **kwargs: Any) -> str:
            await kwargs["on_session_settlement"](
                settlement.SessionSettlementContext(
                    tx_hash="0xdef", channel_id=life.channel_id, trigger="settle", amount=1, delta=1
                )
            )
            return "0xdef"

        async def broken(**kwargs: Any) -> None:
            raise RuntimeError("store down")

        monkeypatch.setattr(settlement, "settle", settled)
        monkeypatch.setattr(settlement, "mark_settlement_complete", broken)
        events: list[settlement.SessionSettlementContext] = []
        channel = await life.channel()
        tx_hash = await scheduled(life, channel, on_session_settlement=events.append)
        assert tx_hash == "0xdef"
        assert [e.trigger for e in events] == ["scheduled"]
        assert (await life.channel()).scheduled_settlement_lease is None

    async def test_long_settlements_renew_their_lease(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life, settled=None)
        renewals: list[str] = []

        async def renew(**kwargs: Any) -> None:
            renewals.append(kwargs["lease_owner"])
            raise RuntimeError("renewal errors are ignored")

        async def slow(*args: Any, **kwargs: Any) -> str:
            await asyncio.sleep(0.05)
            return "0x01"

        monkeypatch.setattr(settlement, "renew_scheduled_settlement", renew)
        monkeypatch.setattr(settlement, "settle", slow)
        tx_hash = await scheduled(life, await life.channel(), lease_ms=20)
        assert tx_hash == "0x01" and renewals

    def test_settlement_sender(self) -> None:
        def check(operator: str, sender: str | None) -> None:
            settlement.assert_settlement_sender(
                operation="settle",
                channel_id="0x1",
                operator=operator,
                payee=PAYEE.address,
                sender=sender,
            )

        check(PAYER.address, PAYER.address)
        with pytest.raises(ValueError, match="no account available"):
            check(ZERO_ADDRESS, None)
        with pytest.raises(BadRequestError, match="or operator"):
            check(PAYER.address, SPONSOR.address)

    @pytest.mark.parametrize(
        ("error", "retryable"),
        [
            *(
                (
                    httpx.HTTPStatusError(
                        "x", request=httpx.Request("POST", RPC), response=httpx.Response(status)
                    ),
                    status != 400,
                )
                for status in (503, 429, 400)
            ),
            (TimeoutError(), True),
            (RuntimeError("RPC error: {'code': -32603, 'message': 'internal'}"), True),
            (RuntimeError("RPC error: {'code': -32000, 'message': 'nonce too low'}"), False),
            (RuntimeError("RPC error: no code"), False),
            (RuntimeError("execution reverted"), False),
        ],
    )
    def test_retryable_failures(self, error: BaseException, retryable: bool) -> None:
        assert settlement.is_retryable_settlement_failure(error) is retryable

    async def test_charge_reports_why_a_channel_cannot_pay(self, life: Lifecycle) -> None:
        await opened(life, finalized=True)
        with pytest.raises(ChannelClosedError, match="finalized"):
            await settlement.charge_session_channel(life.store, life.channel_id, 1)
        await life.update(finalized=False, close_requested_at=5)
        with pytest.raises(ChannelClosedError, match="pending close"):
            await settlement.charge_session_channel(life.store, life.channel_id, 1)
        await life.update(close_requested_at=0)
        with pytest.raises(InsufficientBalanceError, match="available 300"):
            await settlement.charge_session_channel(life.store, life.channel_id, 301)
        with pytest.raises(ChannelClosedError, match="not found"):
            await settlement.charge_session_channel(life.store, "0x" + "ff" * 32, 1)

    async def test_public_charge_and_credit_are_idempotent(self, life: Lifecycle) -> None:
        await opened(life, 500)
        first = await charge(life.raw, life.channel_id, 200, idempotency_key="job-1")
        again = await charge(life.raw, life.channel_id, 200, idempotency_key="job-1")
        assert first.spent == again.spent == 200
        with pytest.raises(IdempotencyKeyConflictError):
            await charge(life.raw, life.channel_id, 300, idempotency_key="job-1")
        await life.update(spent=400, settled_on_chain=100)
        result = await credit(life.raw, life.channel_id, 100, idempotency_key="refund-1")
        assert result.status == "credited" and result.channel is not None
        assert result.channel.spent == 300
        replay = await credit(life.raw, life.channel_id, 100, idempotency_key="refund-1")
        assert replay.status == "credited" and replay.replayed
        declined = await credit(life.raw, life.channel_id, 250, idempotency_key="refund-2")
        assert declined.status == "declined" and declined.reason == "belowSettled"
        with pytest.raises(ValueError, match="idempotency_key"):
            await credit(life.store, life.channel_id, 1, idempotency_key=None)  # type: ignore[arg-type]

    def test_accounting_applies_only_to_content_requests(self) -> None:
        apply = settlement.should_apply_verified_http_accounting
        get = request_state.RequestProbe("GET", httpx.Headers())
        assert apply(request=get, payload_action="open")
        assert not apply(request=None, payload_action="voucher")
        assert not apply(request=get, payload_action="close")

    async def test_accounting_keeps_the_receipt_hash_without_a_settlement(self) -> None:
        receipt = SessionReceipt(
            timestamp="t",
            reference="r",
            challenge_id="c",
            channel_id=CHANNEL_ID,
            accepted_cumulative="10",
            spent="0",
            tx_hash="0xopen",
        )
        charged = bare_channel(deposit=10, highest_voucher_amount=10, spent=5, units=1)

        async def charge_channel(channel_id: str, amount: int) -> ChannelState:
            return charged

        async def no_settlement(channel: ChannelState) -> str | None:
            return None

        async def account(action: str) -> SessionReceipt:
            return await settlement.apply_verified_http_accounting(
                receipt=receipt,
                request=request_state.RequestProbe("GET", httpx.Headers()),
                payload_action=action,
                request_amount=lambda: 5,
                charge=charge_channel,
                settle_charged=no_settlement,
            )

        result = await account("voucher")
        assert (result.spent, result.units, result.tx_hash) == ("5", 1, "0xopen")
        assert await account("topUp") is receipt

    def test_resolve_channel_store(self) -> None:
        wrapped = settlement.resolve_channel_store(MemoryStore())
        assert isinstance(wrapped, StoreChannelStore)
        assert settlement.resolve_channel_store(wrapped) is wrapped


class TestScheduleLeases:
    async def test_lease_helpers_ignore_missing_channels_and_other_owners(
        self, life: Lifecycle
    ) -> None:
        store = life.store
        for helper in (mark_settlement_complete, release_scheduled_settlement):
            await helper(channel_id=life.channel_id, lease_owner="me", store=store)
        await renew_scheduled_settlement(channel_id=life.channel_id, lease_owner="me", store=store)
        assert await store.get_channel(life.channel_id) is None

        await opened(life, spent=300, units=3)
        owner = await claim_scheduled_settlement(
            channel_id=life.channel_id, schedule=ResolvedSettlementSchedule(units=1), store=store
        )
        assert owner is not None
        before = (await life.channel()).scheduled_settlement_lease
        for helper in (
            renew_scheduled_settlement,
            release_scheduled_settlement,
            mark_settlement_complete,
        ):
            await helper(channel_id=life.channel_id, lease_owner="other", store=store)
        assert (await life.channel()).scheduled_settlement_lease == before
        await release_scheduled_settlement(
            channel_id=life.channel_id, lease_owner=owner, store=store
        )
        assert (await life.channel()).scheduled_settlement_lease is None

    async def test_progress_without_a_parseable_timestamp(self, life: Lifecycle) -> None:
        await opened(life, spent=300, created_at="yesterday")
        progress = resolve_settlement_progress(await life.channel())
        assert progress is not None and progress.elapsed_ms is None


# --------------------------------------------------------------------------------------------
# The session method through the engine (Session.test.ts)
# --------------------------------------------------------------------------------------------

URL = "http://api.test/paid"


def make_server(life: Lifecycle, **options: Any) -> Mpp:
    method = tempo_server.session(
        account=PAYEE,
        currency=CURRENCY,
        rpc_url=RPC,
        http_client=life.rpc.client,
        store=life.raw,
        **options,
    )
    return Mpp(methods=[method], realm="api.test", secret_key="secret")


def handler_for(life: Lifecycle, amount: str = "0.0001", **options: Any) -> Any:
    return make_server(life, **options).session(amount=amount, unit_type="request")


def decode_header(value: str) -> dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


async def pay(handler: Any, payload: Any, method: str = "GET", url: str = URL) -> Any:
    challenge = await challenge_for(handler, Request(method, url))
    return await handler(Request(method, url, headers=authorize(challenge, payload.to_wire())))


class TestSessionMethod:
    async def test_chain_id_comes_from_the_rpc_once(self, life: Lifecycle) -> None:
        handler = handler_for(life)
        reads = len(life.rpc.methods("eth_chainId"))
        await challenge_for(handler, Request("GET", URL))
        challenge = await challenge_for(handler, Request("GET", URL))
        assert challenge.request["amount"] == "100"
        assert challenge.request["methodDetails"] == {
            "chainId": CHAIN_ID,
            "escrowContract": ESCROW_ADDRESS,
            "sessionProtocol": "v2",
        }
        assert len(life.rpc.methods("eth_chainId")) == reads + 1

    @pytest.mark.parametrize("engine_store", [False, True])
    async def test_opens_and_charges_through_the_engine(
        self, life: Lifecycle, engine_store: bool
    ) -> None:
        handler = handler_for(life, chain_id=CHAIN_ID)
        if engine_store:
            # Mpp(store=...) reaches a session method configured without its own store.
            method = tempo_server.session(
                account=PAYEE, currency=CURRENCY, rpc_url=RPC, http_client=life.rpc.client
            )
            server = Mpp(methods=[method], realm="api.test", secret_key="secret", store=life.raw)
            handler = server.session(amount="0.0001", unit_type="request")
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        result = await pay(handler, life.open_payload(100))
        assert isinstance(result, PaymentVerified), result
        assert (await life.channel()).spent == 100

    async def test_charges_content_sends_the_mppx_receipt_and_refuses_a_replay(
        self, life: Lifecycle
    ) -> None:
        await opened(life, 100, spent=100, units=1)
        handler = handler_for(life)
        challenge = await challenge_for(handler, Request("GET", URL))
        headers = authorize(challenge, life.voucher_payload(200).to_wire())
        result = await handler(Request("GET", URL, headers=headers))
        assert isinstance(result, PaymentVerified) and result.response is None
        assert isinstance(result.receipt, session.SessionPaymentReceipt)
        receipt = decode_header(result.with_receipt(Response(200)).headers["payment-receipt"])
        assert list(receipt) == [
            "method",
            "intent",
            "status",
            "timestamp",
            "reference",
            "challengeId",
            "channelId",
            "acceptedCumulative",
            "spent",
            "units",
        ]
        assert receipt["spent"] == "200" and receipt["acceptedCumulative"] == "200"
        assert receipt["challengeId"] == challenge.id and receipt["reference"] == life.channel_id
        assert receipt["units"] == 2
        assert len(receipt["timestamp"]) == len("2026-01-01T00:00:00.000Z")
        replay = await handler(Request("GET", URL, headers=headers))
        assert isinstance(replay, PaymentRequired) and replay.status == 402
        assert json.loads(replay.challenge.body or b"")["type"].endswith("/delta-too-small")
        assert (await life.channel()).spent == 200

    async def test_answers_management_requests_with_204(self, life: Lifecycle) -> None:
        await opened(life, 100, spent=100, units=1)
        result = await pay(handler_for(life), life.voucher_payload(300), method="POST")
        assert isinstance(result, PaymentVerified) and result.response is not None
        assert result.response.status == 204
        assert decode_header(result.response.headers["payment-receipt"])["acceptedCumulative"] == (
            "300"
        )
        # A management voucher is accepted but nothing is charged.
        channel = await life.channel()
        assert channel.spent == 100 and channel.highest_voucher_amount == 300

    async def test_insufficient_voucher_is_refused(self, life: Lifecycle) -> None:
        await opened(life, 100, spent=100, units=1)
        result = await pay(handler_for(life, amount="0.0002"), life.voucher_payload(200))
        assert isinstance(result, PaymentRequired)
        assert json.loads(result.challenge.body or b"")["type"].endswith("/insufficient-balance")

    async def test_fee_payer_is_advertised(self, life: Lifecycle) -> None:
        server = make_server(life, fee_payer=SPONSOR, fee_token=CURRENCY)
        handler = server.session(amount="0.0001", unit_type="request", suggested_deposit="1")
        challenge = await challenge_for(handler, Request("GET", URL))
        assert challenge.request["methodDetails"]["feePayer"] is True
        assert challenge.request["methodDetails"]["feeToken"] == CURRENCY
        assert challenge.request["suggestedDeposit"] == "1000000"
        no_sponsor = server.session(amount="0.0001", unit_type="request", fee_payer=False)
        challenge = await challenge_for(no_sponsor, Request("GET", URL))
        assert "feePayer" not in challenge.request["methodDetails"]

    async def test_route_fee_payer_account_sponsors(self) -> None:
        # A route's fee-payer account co-signs the open its challenge advertised (mppx
        # resolveCredentialFeePayer), even on a method configured without one.
        life = await Lifecycle().build(fee_payer=True)
        server = make_server(life, chain_id=CHAIN_ID)
        handler = server.session(amount="0.0001", unit_type="request", fee_payer=SPONSOR)
        challenge = await challenge_for(handler, Request("GET", URL))
        assert challenge.request["methodDetails"]["feePayer"] is True
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        result = await handler(
            Request("GET", URL, headers=authorize(challenge, life.open_payload(100).to_wire()))
        )
        assert isinstance(result, PaymentVerified), result
        assert life.rpc.sent[0].startswith("0x76")
        assert (await life.channel()).spent == 100

    async def test_route_opt_out_refuses_an_earlier_sponsored_reusable_challenge(self) -> None:
        # A reusable challenge issued while the route sponsored fees must not be co-signed once
        # the route sets fee_payer=False (mppx passes feePayer false to resolveCredentialFeePayer).
        life = await Lifecycle().build(fee_payer=True)
        server = make_server(life, chain_id=CHAIN_ID, fee_payer=SPONSOR, reusable_challenges=True)
        sponsored = server.session(amount="0.0001", unit_type="request")
        challenge = await challenge_for(sponsored, Request("GET", URL))
        assert challenge.request["methodDetails"]["feePayer"] is True
        opted_out = server.session(amount="0.0001", unit_type="request", fee_payer=False)
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        await opted_out(
            Request("GET", URL, headers=authorize(challenge, life.open_payload(100).to_wire()))
        )
        # The sponsor never co-signed: nothing sponsored was broadcast.
        assert not any(tx.startswith("0x76") for tx in life.rpc.sent)

    @pytest.mark.parametrize("reusable", [True, False])
    async def test_reusable_challenge_pays_later_price(
        self, life: Lifecycle, reusable: bool
    ) -> None:
        await opened(life, 100, spent=100, units=1)
        server = make_server(life, reusable_challenges=reusable)
        challenge = await challenge_for(
            server.session(amount="0.0001", unit_type="request"), Request("GET", URL)
        )
        # The route's price changed since the challenge was issued.
        pricier = server.session(amount="0.0003", unit_type="request")
        result = await pricier(
            Request("GET", URL, headers=authorize(challenge, life.voucher_payload(400).to_wire()))
        )
        if not reusable:
            assert isinstance(result, PaymentRequired)
            return
        assert isinstance(result, PaymentVerified)
        # Charged the route's current price, not the challenge's quote.
        assert (await life.channel()).spent == 400
        # Still bound to the route: another path is refused.
        other = await pricier(
            Request(
                "GET",
                "http://api.test/other",
                headers=authorize(challenge, life.voucher_payload(700).to_wire()),
            )
        )
        assert isinstance(other, PaymentRequired)

    async def test_scheduled_settlement_through_the_method(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await opened(life, 100, spent=100, units=1)

        async def settled(*args: Any, **kwargs: Any) -> str:
            await kwargs["on_session_settlement"](
                settlement.SessionSettlementContext(
                    tx_hash="0xdef",
                    channel_id=life.channel_id,
                    trigger="settle",
                    amount=200,
                    delta=200,
                )
            )
            return "0xdef"

        monkeypatch.setattr(settlement, "settle", settled)
        settlements: list[settlement.SessionSettlementContext] = []
        handler = handler_for(
            life,
            settlement_schedule=SettlementSchedule(units=2),
            on_session_settlement=settlements.append,
        )
        result = await pay(handler, life.voucher_payload(200))
        assert isinstance(result, PaymentVerified)
        assert decode_header(result.receipt.to_payment_receipt())["txHash"] == "0xdef"
        assert [(s.trigger, s.amount) for s in settlements] == [("scheduled", 200)]

    async def test_scheduled_settlement_failure_keeps_the_request_served(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await life.open(100)

        async def down(*args: Any, **kwargs: Any) -> str:
            raise httpx.ConnectError("node down")

        monkeypatch.setattr(chain, "settle_on_chain", down)
        handler = handler_for(life, settlement_schedule=SettlementSchedule(units=1))
        result = await pay(handler, life.voucher_payload(200))
        assert isinstance(result, PaymentVerified), result
        assert result.receipt.to_payment_receipt()
        assert (await life.channel()).spent == 100

    async def test_needs_a_recipient(self) -> None:
        method = tempo_server.session(chain_id=CHAIN_ID, rpc_url=RPC, store=MemoryStore())
        handler = Mpp(methods=[method], realm="api.test", secret_key="s").session(
            amount="1", unit_type="request"
        )
        with pytest.raises(ValueError, match="needs a recipient"):
            await handler(Request("GET", URL))

    def test_factory_reads_the_request_body_and_is_exported(self) -> None:
        from mpp.methods.tempo.session import server as session_server

        # A POST is content only when it has a body, so adapters must pass the body through.
        method = tempo_server.session(account=PAYEE, rpc_url=RPC, store=MemoryStore())
        assert method.key == "tempo/session" and method.respond is not None
        assert method.stable_binding is None and method.needs_request_body
        handler = Mpp(methods=[method], realm="api.test", secret_key="s").session(
            amount="1", unit_type="request"
        )
        assert handler.needs_request_body
        assert callable(session_server.charge) and callable(session_server.supervise_closes)

    def test_fee_payer_true_needs_an_account(self) -> None:
        with pytest.raises(ValueError, match="requires an account"):
            tempo_server.session(
                fee_payer=True, chain_id=CHAIN_ID, rpc_url=RPC, store=MemoryStore()
            )
        method = tempo_server.session(account=PAYEE, fee_payer=True, store=MemoryStore())
        assert method.key == "tempo/session"

    def test_warns_once_without_a_store(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(session, "_warned_fallback_store", False)
        with caplog.at_level(logging.WARNING, logger=session.__name__):
            # The fallback is created on first use, after Mpp(store=...) could supply one.
            tempo_server.session(account=PAYEE)
            assert not caplog.records
            session._fallback_store()  # pyright: ignore[reportPrivateUsage]
            session._fallback_store()  # pyright: ignore[reportPrivateUsage]
        assert [r.message.count("in-memory store") for r in caplog.records] == [1]

    def test_receipt_without_session_fields(self) -> None:
        receipt = session.SessionPaymentReceipt(
            status="success", timestamp=datetime.now(UTC), reference="ref", method="tempo"
        )
        assert receipt.to_payment_receipt()

    async def test_mcp_tool_calls_are_charged_and_a_replayed_voucher_rejected(
        self, life: Lifecycle
    ) -> None:
        # An MCP tool call is a billable content request (mppx's MCP transports set hasBody).
        from mpp.extensions.mcp import MCPCredential, verify_or_challenge
        from mpp.extensions.mcp.errors import PaymentVerificationError

        handler = handler_for(life, chain_id=CHAIN_ID)

        async def call(payload: Any) -> Any:
            challenges = await verify_or_challenge(handler, tool="search")
            assert isinstance(challenges, list)
            [challenge] = challenges
            credential = MCPCredential(
                challenge=challenge, payload=payload.to_wire(), source=SOURCE
            )
            return await verify_or_challenge(handler, tool="search", meta=credential.to_meta())

        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        assert isinstance(await call(life.open_payload(100)), tuple)
        for amount in (200, 300):
            assert isinstance(await call(life.voucher_payload(amount)), tuple)
            assert (await life.channel()).spent == amount
        assert (await life.channel()).units == 3
        with pytest.raises(PaymentVerificationError):
            await call(life.voucher_payload(300))
        assert (await life.channel()).spent == 300


class TestEngineHooks:
    def test_server_method_checks_its_hooks(self) -> None:
        from mpp.methods.tempo.session._protocol import definition
        from mpp.server.method import ServerMethod

        async def verify(context: Any) -> Any:
            raise AssertionError

        with pytest.raises(ValueError, match="respond must be callable"):
            ServerMethod(method=definition, verify=verify, respond="204")  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="stable_binding must be callable"):
            ServerMethod(method=definition, verify=verify, stable_binding={})  # type: ignore[arg-type]

    def test_stable_binding_compares_scope_and_bound_fields(self) -> None:
        from mpp.server.verify import _requests_match

        def binding(request: Any) -> dict[str, Any]:
            return {"recipient": request["recipient"]}

        echoed = {"_mppx_scope": "/paid", "recipient": "a", "amount": "1"}
        assert _requests_match(echoed, {**echoed, "amount": "2"}, binding)
        assert not _requests_match(echoed, {**echoed, "_mppx_scope": "/other"}, binding)
        assert not _requests_match(echoed, {"_mppx_scope": "/paid"}, binding)
        assert not _requests_match(echoed, {**echoed, "amount": "2"}, None)


# --------------------------------------------------------------------------------------------
# Channel store edges
# --------------------------------------------------------------------------------------------


class DictStore:
    """A store without compare-and-set: updates are serialized in this process only."""

    __slots__ = ("data",)

    def __init__(self) -> None:
        self.data: dict[str, Any] = {}

    async def get(self, key: str) -> Any | None:
        return self.data.get(key)

    async def put(self, key: str, value: Any) -> None:
        self.data[key] = value

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)


class BytesCasStore(DictStore):
    """A store that keeps values as bytes and compares expected values as given."""

    async def put_if_absent(self, key: str, value: Any) -> bool:
        return self.data.setdefault(key, value) is value

    async def compare_and_set(self, key: str, expected: Any, value: Any) -> bool:
        if self.data.get(key) != expected:
            return False
        if value is None:
            self.data.pop(key, None)
        else:
            self.data[key] = value.encode() if isinstance(value, str) else value
        return True


class RefusingCasStore(BytesCasStore):
    """A store whose compare_and_set is refused, like Redis denying EVAL."""

    __slots__ = ("attempts",)

    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    async def compare_and_set(self, key: str, expected: Any, value: Any) -> bool:
        self.attempts += 1
        raise NotImplementedError("EVAL denied")


class WriteRefusingCasStore(BytesCasStore):
    """A store whose compare_and_set refuses only writes, like Redis without KEEPTTL."""

    async def compare_and_set(self, key: str, expected: Any, value: Any) -> bool:
        if value is not None:
            raise NotImplementedError("SET KEEPTTL: syntax error")
        return await super().compare_and_set(key, expected, value)


class DeleteRefusingCasStore(BytesCasStore):
    """A store that writes but refuses deletes, like a Redis ACL that denies DEL."""

    async def compare_and_set(self, key: str, expected: Any, value: Any) -> bool:
        if value is None:
            raise NotImplementedError("DEL denied")
        return await super().compare_and_set(key, expected, value)


class TestChannelStore:
    async def test_non_atomic_store_sets_and_deletes(self, life: Lifecycle) -> None:
        raw = DictStore()
        # A store that cannot be weakly referenced still gets one adapter, so its per-key
        # locks serialize every update made through from_store.
        channel_store = from_store(raw)  # type: ignore[arg-type]
        assert channel_store is from_store(raw)  # type: ignore[arg-type]
        assert from_store(DictStore()) is not channel_store  # type: ignore[arg-type]
        assert channel_store.store is raw and not channel_store.atomic
        life.store = channel_store
        await life.open(300)
        assert (await life.channel()).highest_voucher_amount == 300
        for store in (channel_store, from_store(MemoryStore())):
            with pytest.raises(ValueError, match="needs a value"):
                await store.update_channel_result(
                    life.channel_id, lambda c: store_module.StoreChange("set", None)
                )
        deleted = await channel_store.update_channel_result(
            life.channel_id, lambda c: store_module.StoreChange("delete", "gone")
        )
        assert deleted == "gone" and raw.data == {}

    async def test_apply_change_on_a_custom_channel_store(self, life: Lifecycle) -> None:
        await life.open(300)

        class Wrapped:
            """A channel store that is not the pympp adapter."""

            async def get_channel(self, channel_id: str) -> ChannelState | None:
                return await life.store.get_channel(channel_id)

            async def update_channel(self, channel_id: str, fn: Any) -> ChannelState | None:
                return await life.store.update_channel(channel_id, fn)

        result = await store_module._apply_change(
            Wrapped(), life.channel_id, lambda c: store_module.StoreChange("delete", 7)
        )
        assert result == 7 and await life.store.get_channel(life.channel_id) is None
        with pytest.raises(ChannelNotFoundError):
            await store_module.deduct_from_channel(
                Wrapped(), life.channel_id, 1, idempotency_key="k"
            )
        # Session charges report a missing channel as closed.
        with pytest.raises(ChannelClosedError, match="not found"):
            await settlement.charge_session_channel(
                Wrapped(), life.channel_id, 1, idempotency_key="k"
            )

    async def test_state_codec_rejects_malformed_records(self, life: Lifecycle) -> None:
        await life.open(300)
        channel = await life.channel()
        record = store_module.channel_state_to_json(channel)
        assert store_module.channel_state_from_json(record) == channel
        bare = replace(
            channel,
            backend=None,
            descriptor=None,
            expiring_nonce_hash=None,
            operator=None,
            salt=None,
            on_chain_verified_at=None,
        )
        assert (
            store_module.channel_state_from_json(store_module.channel_state_to_json(bare)) == bare
        )
        assert store_module.channel_state_from_json({**record, "deposit": 5.0}).deposit == 5
        markers = {"charge:k": {"amount": "1", "expiresAt": "1", "outcome": "lost"}}
        for broken in (
            {**record, "deposit": True},
            {**record, "deposit": 1.5},
            {**record, "deposit": None},
            {**record, "backend": "magic"},
            {**record, "highestVoucher": "0x"},
            {**record, "idempotencyMarkers": markers},
        ):
            with pytest.raises((ValueError, TypeError)):
                store_module.channel_state_from_json(broken)

    def test_settleable_voucher_prefers_the_largest_within_spent(self) -> None:
        state = bare_channel(
            settled_on_chain=100,
            spent=500,
            retained_vouchers=(
                RetainedVoucher(100, "0x01"),
                RetainedVoucher(400, "0x04"),
                RetainedVoucher(300, "0x03"),
                RetainedVoucher(600, "0x06"),
            ),
        )
        voucher = resolve_settleable_voucher(state)
        assert voucher is not None
        assert (voucher.cumulative_amount, voucher.signature) == (400, "0x04")

    def test_close_helpers_on_missing_or_finalized_channels(self) -> None:
        assert (
            store_module.finalize_closed_channel_state(
                capture_amount=1,
                channel_id=CHANNEL_ID,
                cumulative_amount=1,
                current=None,
                signature="0x",
            )
            is None
        )
        mark = store_module.mark_pending_close
        options: dict[str, Any] = {
            "close_requested_at": 1,
            "cumulative_amount": 1,
            "on_chain_deposit": 1_000,
            "on_chain_settled": 0,
        }
        assert mark(current=None, **options).state is None
        with pytest.raises(ChannelClosedError, match="already finalized"):
            mark(current=bare_channel(finalized=True), **options)

    def test_released_store_and_adapter_are_collected(self) -> None:
        raw = MemoryStore()
        adapter = from_store(raw)
        assert from_store(raw) is adapter
        ref = weakref.ref(raw)
        del raw, adapter
        gc.collect()
        assert ref() is None


class TestCompareAndSetRefused:
    async def test_open_fails_before_broadcast(self, life: Lifecycle) -> None:
        raw = RefusingCasStore()
        channel_store = StoreChannelStore(raw)
        assert channel_store.atomic
        life.store = channel_store
        with pytest.raises(NotImplementedError, match="refused compare_and_set"):
            await life.open(300)
        # Nothing was broadcast and nothing was stored: the payer's deposit never moved.
        assert not life.rpc.sent
        assert raw.attempts == 1 and not raw.data
        assert channel_store.atomic

    async def test_top_up_fails_before_broadcast(self, life: Lifecycle) -> None:
        await life.open(300)
        sent = len(life.rpc.sent)
        raw = RefusingCasStore()
        raw.data.update(life.raw._data)  # pyright: ignore[reportPrivateUsage]
        payload = await life.top_up_payload(500)
        with pytest.raises(NotImplementedError, match="refused compare_and_set"):
            await life.accept(payload, store=StoreChannelStore(raw))
        assert len(life.rpc.sent) == sent

    async def test_updates_raise_instead_of_dropping_atomicity(self, life: Lifecycle) -> None:
        await life.open(300)
        raw = RefusingCasStore()
        raw.data.update(life.raw._data)  # pyright: ignore[reportPrivateUsage]
        channel_store = StoreChannelStore(raw)
        for _ in range(2):
            with pytest.raises(NotImplementedError, match="refused compare_and_set"):
                await channel_store.update_channel(
                    life.channel_id, lambda c: replace(c, spent=10) if c else c
                )
        assert raw.attempts == 2 and channel_store.atomic
        assert (await channel_store.get_channel(life.channel_id)).spent == 0  # type: ignore[union-attr]

    async def test_probe_exercises_the_write_a_channel_update_makes(self, life: Lifecycle) -> None:
        # Like Redis without KEEPTTL: a CAS that only reads or deletes succeeds, a write fails.
        raw = WriteRefusingCasStore()
        life.store = StoreChannelStore(raw)
        with pytest.raises(NotImplementedError, match="refused compare_and_set"):
            await life.open(300)
        assert not life.rpc.sent and not raw.data

    async def test_probe_runs_once_and_changes_nothing(self, life: Lifecycle) -> None:
        await life.open(300)
        before = dict(life.raw._data)  # pyright: ignore[reportPrivateUsage]
        await check_atomic_update(life.store, life.channel_id)
        await check_atomic_update(life.store, "0x" + "ab" * 32)
        assert life.raw._data == before  # pyright: ignore[reportPrivateUsage]

    async def test_probe_on_bytes_stores(self) -> None:
        raw = BytesCasStore()
        channel_store = StoreChannelStore(raw)
        await channel_store.check_atomic_update("0x" + "ab" * 32)
        assert not raw.data
        # Concurrent probes on one adapter never refuse.
        await asyncio.gather(
            *(channel_store.check_atomic_update("0x" + "ab" * 32) for _ in range(20))
        )
        assert not raw.data
        # An earlier probe on this adapter wrote its key, then was interrupted.
        leftover = StoreChannelStore(raw)
        raw.data[leftover._cas_probe_key] = b"1"  # pyright: ignore[reportPrivateUsage]
        await leftover.check_atomic_update("0x" + "ab" * 32)
        assert not raw.data

    async def test_failed_cleanup_leaves_one_key_per_adapter(self) -> None:
        raw = DeleteRefusingCasStore()
        for _ in range(3):
            await StoreChannelStore(raw).check_atomic_update("0x" + "ab" * 32)
        assert len(raw.data) == 3
        assert all(key.startswith("mpp:session:cas-probe:") for key in raw.data)
