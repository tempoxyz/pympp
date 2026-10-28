"""Session server units against a fake node: verification, settlement, request state, the method.

Ports cases of mppx server/CredentialVerification.test.ts, Settlement.test.ts, RequestState.test.ts
and Session.test.ts. Client-signed transactions are built offline (tests/test_session_chain.py's
fake JSON-RPC node), so open, top-up, voucher and close run through the real chain layer.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.errors import BadRequestError, VerificationFailedError
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo.session import chain
from mpp.methods.tempo.session.channel import compute_channel_id
from mpp.methods.tempo.session.protocol import (
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
from mpp.methods.tempo.session.server import request_state, settlement, verification
from mpp.methods.tempo.session.server.schedule import (
    ResolvedSettlementSchedule,
    claim_scheduled_settlement,
    mark_settlement_complete,
    release_scheduled_settlement,
    renew_scheduled_settlement,
    resolve_settlement_progress,
)
from mpp.methods.tempo.session.server.store import (
    AmountExceedsDepositError,
    ChannelClosedError,
    ChannelNotFoundError,
    ChannelState,
    DeltaTooSmallError,
    InsufficientBalanceError,
    InvalidSignatureError,
    StoreChannelStore,
    check_atomic_update,
    from_store,
)
from mpp.methods.tempo.session.server.verification import CredentialContext
from mpp.methods.tempo.session.voucher import sign_close_authorization, sign_voucher
from mpp.server import Mpp, PaymentRequired, PaymentVerified, Request
from mpp.store import MemoryStore
from tests.test_session_chain import (
    CHAIN_ID,
    CURRENCY,
    DEPOSIT,
    OTHER_TOKEN,
    PAYEE,
    PAYER,
    RPC,
    SPONSOR,
    FakeRpc,
    event_log,
    fail,
    opened_log,
    top_up_log,
)

SOURCE = f"did:pkh:eip155:{CHAIN_ID}:{PAYER.address}"
# The package exports the session() factory under the module's name.
session = importlib.import_module("mpp.methods.tempo.session.server.session")


def make_challenge(amount: str = "100", **details: Any) -> Challenge:
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    return Challenge(
        id="challenge-1",
        method="tempo",
        intent="session",
        request={
            "amount": amount,
            "currency": CURRENCY,
            "recipient": PAYEE.address,
            "unitType": "request",
            "methodDetails": {
                "chainId": CHAIN_ID,
                "escrowContract": ESCROW_ADDRESS,
                "sessionProtocol": "v2",
                **details,
            },
        },
        expires=expires,
    )


def closed_log(descriptor: ChannelDescriptor, channel_id: str, paid: int, refund: int) -> Any:
    return event_log("ChannelClosed", descriptor, channel_id, ["uint96", "uint96"], [paid, refund])


def sign(channel_id: str, amount: int, account: Any = PAYER) -> str:
    return sign_voucher(account, channel_id=channel_id, cumulative_amount=amount, chain_id=CHAIN_ID)


class Lifecycle:
    """One channel driven through the real verification and chain code by a fake node."""

    def __init__(self) -> None:
        self.rpc = FakeRpc()
        self.raw = MemoryStore()
        self.store = from_store(self.raw)
        self.descriptor: ChannelDescriptor
        self.channel_id = ""
        self.transaction = ""
        self.last_verified: dict[str, int] = {}

    async def build(self, **kwargs: Any) -> Lifecycle:
        self.transaction, self.descriptor, self.channel_id = await chain.build_open_transaction(
            PAYER,
            rpc_url=RPC,
            payee=PAYEE.address,
            token=CURRENCY,
            deposit=DEPOSIT,
            client=self.rpc.client,
            **kwargs,
        )
        return self

    def context(self, payload: Any, **overrides: Any) -> CredentialContext:
        fields: dict[str, Any] = {
            "challenge": make_challenge(),
            "payload": payload,
            "chain_id": CHAIN_ID,
            "escrow": ESCROW_ADDRESS,
            "rpc_url": RPC,
            "store": self.store,
            "account": PAYEE,
            "http_client": self.rpc.client,
            "credential_source": SOURCE,
            "last_on_chain_verified": self.last_verified,
        }
        fields.update(overrides)
        return CredentialContext(**fields)

    def open_payload(self, amount: int = 100, **overrides: Any) -> OpenPayload:
        wire: dict[str, Any] = {
            "action": "open",
            "type": "transaction",
            "channelId": self.channel_id,
            "transaction": self.transaction,
            "signature": sign(self.channel_id, amount),
            "descriptor": self.descriptor.to_wire(),
            "cumulativeAmount": str(amount),
        }
        wire.update(overrides)
        return OpenPayload.model_validate(wire)

    def voucher_payload(self, amount: int, **overrides: Any) -> VoucherPayload:
        wire: dict[str, Any] = {
            "action": "voucher",
            "channelId": self.channel_id,
            "descriptor": self.descriptor.to_wire(),
            "cumulativeAmount": str(amount),
            "signature": sign(self.channel_id, amount),
        }
        wire.update(overrides)
        return VoucherPayload.model_validate(wire)

    async def top_up_payload(self, amount: int = 500) -> TopUpPayload:
        raw = await chain.build_top_up_transaction(
            PAYER, self.descriptor, amount, rpc_url=RPC, client=self.rpc.client
        )
        return TopUpPayload.model_validate(
            {
                "action": "topUp",
                "type": "transaction",
                "channelId": self.channel_id,
                "transaction": raw,
                "descriptor": self.descriptor.to_wire(),
                "additionalDeposit": str(amount),
            }
        )

    def close_payload(self, amount: int, *, close_signer: Any = PAYER) -> ClosePayload:
        return ClosePayload.model_validate(
            {
                "action": "close",
                "channelId": self.channel_id,
                "descriptor": self.descriptor.to_wire(),
                "cumulativeAmount": str(amount),
                "signature": sign(self.channel_id, amount),
                "closeSignature": sign_close_authorization(
                    close_signer,
                    channel_id=self.channel_id,
                    cumulative_amount=amount,
                    chain_id=CHAIN_ID,
                ),
            }
        )

    async def open(self, amount: int = 100, **overrides: Any) -> SessionReceipt:
        self.rpc.logs = [opened_log(self.descriptor, self.channel_id)]
        return await verification.broadcast_credential_payload(
            self.context(self.open_payload(amount), **overrides)
        )

    async def channel(self) -> ChannelState:
        channel = await self.store.get_channel(self.channel_id)
        assert channel is not None
        return channel

    async def update(self, **fields: Any) -> None:
        await self.store.update_channel(self.channel_id, lambda c: replace(c, **fields) if c else c)


@pytest.fixture
async def life() -> Lifecycle:
    return await Lifecycle().build()


# --------------------------------------------------------------------------------------------
# Full lifecycle through the chain layer
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
        assert opened.tx_hash == life.rpc.sent[0][:0] + "0x" + f"{1:064x}"
        assert opened.accepted_cumulative == "100" and life.last_verified[life.channel_id] > 0
        channel = await life.channel()
        assert channel.deposit == DEPOSIT and channel.descriptor == life.descriptor

        receipt = await verification.broadcast_credential_payload(
            life.context(life.voucher_payload(300))
        )
        assert receipt.accepted_cumulative == "300" and receipt.tx_hash is None

        top_up = await life.top_up_payload()
        await verification.validate_credential_payload(life.context(top_up))
        life.rpc.logs = [top_up_log(life.descriptor, life.channel_id, 500, DEPOSIT + 500)]
        life.rpc.states[life.channel_id] = (0, DEPOSIT + 500, 0)
        topped = await verification.broadcast_credential_payload(life.context(top_up))
        assert topped.accepted_cumulative == "300" and topped.tx_hash is not None
        assert (await life.channel()).deposit == DEPOSIT + 500

        await life.update(spent=250)
        close = life.close_payload(300)
        await verification.validate_credential_payload(life.context(close))
        life.rpc.logs = [closed_log(life.descriptor, life.channel_id, 250, DEPOSIT + 250)]
        closed = await verification.broadcast_credential_payload(
            life.context(close, on_session_settlement=settlements.append)
        )
        assert closed.accepted_cumulative == "300" and closed.spent == "250"
        channel = await life.channel()
        assert channel.finalized and channel.settled_on_chain == 250
        assert [(s.trigger, s.amount, s.delta) for s in settlements] == [("close", 250, 250)]

    async def test_open_rejects_a_mismatched_authorized_signer(self, life: Lifecycle) -> None:
        payload = life.open_payload(authorizedSigner=PAYEE.address)
        with pytest.raises(VerificationFailedError, match="authorizedSigner"):
            await verification.validate_credential_payload(life.context(payload))
        with pytest.raises(VerificationFailedError, match="authorizedSigner"):
            await verification.broadcast_credential_payload(life.context(payload))
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

    async def test_open_replay_must_advance_for_content(self, life: Lifecycle) -> None:
        await life.open(300)
        with pytest.raises(DeltaTooSmallError):
            await life.open(300, require_voucher_advance=True)

    async def test_sponsored_open_advertises_both_fee_tokens(self) -> None:
        life = await Lifecycle().build(fee_payer=True, fee_token=OTHER_TOKEN)
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        context = life.context(life.open_payload(), fee_payer=SPONSOR, fee_token=OTHER_TOKEN)
        receipt = await verification.broadcast_credential_payload(context)
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


class TestVoucherChecks:
    async def test_validation_rejects_a_finalized_channel(self, life: Lifecycle) -> None:
        await life.open()
        await life.update(finalized=True)
        with pytest.raises(ChannelClosedError, match="finalized"):
            await verification.validate_credential_payload(life.context(life.voucher_payload(200)))

    async def test_rejects_a_record_that_is_not_precompile_backed(self, life: Lifecycle) -> None:
        await life.open()
        await life.update(backend="contract")
        with pytest.raises(VerificationFailedError, match="not precompile-backed"):
            await verification.validate_credential_payload(life.context(life.voucher_payload(200)))

    async def test_expired_local_close_marker_is_cleared_by_a_voucher(
        self, life: Lifecycle
    ) -> None:
        await life.open()
        await life.update(close_requested_at=1_000)
        receipt = await verification.broadcast_credential_payload(
            life.context(life.voucher_payload(200))
        )
        assert receipt.accepted_cumulative == "200"
        assert (await life.channel()).close_requested_at == 0

    async def test_pending_close_on_chain_without_deposit_is_only_recorded(
        self, life: Lifecycle
    ) -> None:
        await life.open()
        sent = len(life.rpc.sent)
        life.rpc.states[life.channel_id] = (40, 0, 1_700_000_000)
        with pytest.raises(ChannelClosedError, match="pending close"):
            await verification.broadcast_credential_payload(life.context(life.voucher_payload(200)))
        channel = await life.channel()
        assert channel.close_requested_at == 1_700_000_000 and channel.settled_on_chain == 40
        # Nothing was settled: the deposit already left.
        assert len(life.rpc.sent) == sent

    async def test_store_errors_win_over_the_chain_read(self, life: Lifecycle) -> None:
        with pytest.raises(ChannelNotFoundError):
            await verification.broadcast_credential_payload(life.context(life.voucher_payload(200)))

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

    @pytest.mark.parametrize("field", ["cumulativeAmount"])
    async def test_amounts_beyond_uint96_are_verification_failures(
        self, life: Lifecycle, field: str
    ) -> None:
        await life.open()
        payload = life.voucher_payload(200, **{field: str(1 << 96)})
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
    async def _opened(self, life: Lifecycle, **fields: Any) -> None:
        await life.open(300)
        if fields:
            await life.update(**fields)

    async def test_rejects_a_finalized_channel(self, life: Lifecycle) -> None:
        await self._opened(life, finalized=True)
        with pytest.raises(ChannelClosedError, match="already finalized"):
            await verification.validate_credential_payload(life.context(life.close_payload(300)))

    @pytest.mark.parametrize(
        ("state", "amount", "error", "match"),
        [
            ((0, DEPOSIT, 1_700_000_000), 300, ChannelClosedError, "pending close"),
            ((0, 0, 0), 300, ChannelClosedError, "deposit is zero"),
            ((400, DEPOSIT, 0), 300, VerificationFailedError, "on-chain settled"),
            ((0, 200, 0), 300, AmountExceedsDepositError, "exceeds on-chain deposit"),
        ],
    )
    async def test_checks_on_chain_state(
        self,
        life: Lifecycle,
        state: tuple[int, int, int],
        amount: int,
        error: type[Exception],
        match: str,
    ) -> None:
        await self._opened(life, spent=250)
        life.rpc.states[life.channel_id] = state
        with pytest.raises(error, match=match):
            await verification.validate_credential_payload(life.context(life.close_payload(amount)))

    async def test_rejects_a_voucher_signature_by_another_key(self, life: Lifecycle) -> None:
        await self._opened(life)
        close = life.close_payload(300).model_copy(
            update={"signature": sign(life.channel_id, 300, PAYEE)}
        )
        with pytest.raises(InvalidSignatureError, match="invalid voucher signature"):
            await verification.validate_credential_payload(life.context(close))

    async def test_rejects_close_amounts_the_event_contradicts(self, life: Lifecycle) -> None:
        await self._opened(life, spent=250)
        life.rpc.logs = [closed_log(life.descriptor, life.channel_id, 260, 0)]
        close = life.close_payload(300)
        with pytest.raises(VerificationFailedError, match="ChannelClosed amounts"):
            await verification.broadcast_credential_payload(life.context(close))

    async def test_reverted_close_clears_its_pending_marker(self, life: Lifecycle) -> None:
        await self._opened(life, spent=250)
        life.rpc.receipt_status = "0x0"
        failures: list[settlement.SessionSettlementFailureContext] = []
        with pytest.raises(VerificationFailedError, match="reverted"):
            await verification.broadcast_credential_payload(
                life.context(life.close_payload(300), on_session_settlement_failure=failures.append)
            )
        assert (await life.channel()).close_requested_at == 0
        assert [f.trigger for f in failures] == ["close"]

    async def test_close_that_would_revert_is_never_sent(self, life: Lifecycle) -> None:
        # A withdrawn channel (deposit 0, nothing spent) passes validation with a zero close,
        # as in mppx; its gas estimate fails, so like viem nothing is broadcast.
        await self._opened(life)
        life.rpc.states[life.channel_id] = (0, 0, 0)
        life.rpc.overrides["eth_estimateGas"] = fail("execution reverted")
        sent = len(life.rpc.sent)
        for _ in range(2):
            with pytest.raises(RuntimeError, match="execution reverted"):
                await verification.broadcast_credential_payload(life.context(life.close_payload(0)))
            assert (await life.channel()).close_requested_at == 0
        assert len(life.rpc.sent) == sent

    async def test_close_without_a_caller_client(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._opened(life, spent=250)
        real_client = httpx.AsyncClient
        transport = httpx.MockTransport(life.rpc._handle)
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(transport=transport))
        life.rpc.logs = [closed_log(life.descriptor, life.channel_id, 250, DEPOSIT - 250)]
        receipt = await verification.broadcast_credential_payload(
            life.context(life.close_payload(300), http_client=None)
        )
        assert receipt.tx_hash is not None and (await life.channel()).finalized


# --------------------------------------------------------------------------------------------
# Payload and descriptor checks
# --------------------------------------------------------------------------------------------


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

    def test_credential_source_must_be_a_did_pkh_address(self) -> None:
        channel = ChannelState(
            channel_id=CHANNEL_ID,
            authorized_signer=PAYER.address,
            chain_id=CHAIN_ID,
            escrow_contract=ESCROW_ADDRESS,
            payer=PAYER.address,
            payee=PAYEE.address,
            token=CURRENCY,
            deposit=1,
            settled_on_chain=0,
            highest_voucher_amount=0,
            highest_voucher=None,
            spent=0,
            units=0,
            close_requested_at=0,
            finalized=False,
            created_at="2026-01-01T00:00:00.000Z",
        )
        verification.assert_credential_source_can_spend(
            chain_id=CHAIN_ID, channel=channel, source=SOURCE.lower()
        )
        with pytest.raises(VerificationFailedError, match="invalid credential source"):
            verification.assert_credential_source_can_spend(
                chain_id=CHAIN_ID, channel=channel, source=f"did:pkh:eip155:{CHAIN_ID}:0x12"
            )
        with pytest.raises(VerificationFailedError, match="does not match channel"):
            verification.assert_credential_source_can_spend(
                chain_id=CHAIN_ID, channel=channel, source=None
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
        with pytest.raises(VerificationFailedError, match="action"):
            request_state.respond_to_session_credential(payload_action="settle", request=None)
        assert (
            request_state.respond_to_session_credential(payload_action="open", request=None) is None
        )
        close = request_state.respond_to_session_credential(payload_action="close", request=None)
        assert close is not None and close.status == 204
        get = Request("GET", "http://api.test/paid")
        assert (
            request_state.respond_to_session_credential(payload_action="voucher", request=get)
            is None
        )
        head = request_state.respond_to_session_credential(
            payload_action="voucher", request=Request("HEAD", "http://api.test/paid")
        )
        assert head is not None and head.status == 204

    def test_fee_payer_resolution(self) -> None:
        resolve = request_state.resolve_request_fee_payer
        assert resolve(default_fee_payer=SPONSOR, request_fee_payer=False) is None
        # A route's own account is kept for verification; the wire advertises it as true.
        assert resolve(default_fee_payer=None, request_fee_payer=SPONSOR) is SPONSOR
        assert resolve(default_fee_payer=None, request_fee_payer=True) is None
        assert resolve(default_fee_payer=SPONSOR) is True
        assert resolve(default_fee_payer=None) is None
        credential = request_state.resolve_credential_fee_payer
        assert credential(method_details={"feePayer": True}, fee_payer=SPONSOR) is SPONSOR
        assert credential(method_details={"feePayer": "true"}, fee_payer=SPONSOR) is None
        route = credential(
            method_details={"feePayer": True}, fee_payer=None, request_fee_payer=PAYEE
        )
        assert route is PAYEE
        assert (
            credential(method_details={"feePayer": True}, fee_payer=SPONSOR, request_fee_payer=True)
            is SPONSOR
        )
        assert (
            credential(
                method_details={"feePayer": True}, fee_payer=SPONSOR, request_fee_payer=False
            )
            is None
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
        "details",
        [
            {"chainId": True},
            {"chainId": "1337"},
            {"escrowContract": "0x12"},
            {"feePayer": "yes"},
            {"feeToken": "usd"},
            {"minVoucherDelta": 5},
            {"operator": "0x12"},
            {"sessionProtocol": "v1"},
        ],
    )
    def test_method_details_are_checked(self, details: dict[str, Any]) -> None:
        with pytest.raises(VerificationFailedError, match="invalid session request"):
            request_state.read_method_details(make_challenge(**details).request)

    def test_method_details_need_an_object_and_string_fields(self) -> None:
        request = make_challenge().request
        with pytest.raises(VerificationFailedError, match="invalid session request"):
            request_state.read_method_details({**request, "methodDetails": None})
        with pytest.raises(VerificationFailedError, match="invalid session request"):
            request_state.read_method_details({**request, "unitType": 1})
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
        resolve = request_state.resolve_session_payment_request
        resolved = resolve(
            request={"amount": "1", "chainId": 4217, "operator": PAYEE.address, "feePayer": False},
            chain_id=CHAIN_ID,
            default_fee_payer=SPONSOR,
            parameter_escrow_contract=None,
            fee_token=CURRENCY,
        )
        assert resolved == {
            "amount": "1",
            "chain_id": 4217,
            "escrow_contract": ESCROW_ADDRESS,
            "operator": PAYEE.address,
            "fee_token": CURRENCY,
            "session_protocol": "v2",
        }
        custom = resolve(
            request={"escrowContract": PAYER.address},
            chain_id=CHAIN_ID,
            default_fee_payer=None,
            parameter_escrow_contract=None,
            fee_token=None,
        )
        assert custom["escrow_contract"] == PAYER.address and "fee_payer" not in custom
        with pytest.raises(ValueError, match="escrow_contract"):
            resolve(
                request={"escrow_contract": "0x12"},
                chain_id=CHAIN_ID,
                default_fee_payer=None,
                parameter_escrow_contract=None,
                fee_token=None,
            )
        with pytest.raises(ValueError, match="operator"):
            resolve(
                request={"operator": "0x12"},
                chain_id=CHAIN_ID,
                default_fee_payer=None,
                parameter_escrow_contract=None,
                fee_token=None,
            )


# --------------------------------------------------------------------------------------------
# Settlement (Settlement.test.ts)
# --------------------------------------------------------------------------------------------


def settled_log(descriptor: ChannelDescriptor, channel_id: str, amount: int, delta: int) -> Any:
    return event_log(
        "Settled",
        descriptor,
        channel_id,
        ["uint96", "uint96", "uint96"],
        [amount, delta, amount],
    )


class TestSettle:
    async def _ready(self, life: Lifecycle, *, spent: int = 300) -> None:
        await life.open(300)
        await life.update(spent=spent, units=3)

    async def test_settles_through_the_chain_and_records_it(self, life: Lifecycle) -> None:
        await self._ready(life)
        life.rpc.logs = [settled_log(life.descriptor, life.channel_id, 300, 300)]
        life.rpc.states[life.channel_id] = (300, DEPOSIT, 0)
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
        assert channel.pending_settlement is None
        assert [(e.amount, e.delta) for e in events] == [(300, 300)]
        # Settlement reads back at the receipt's block.
        assert life.rpc.methods("eth_call")[-1][1] == "0x10"

    async def test_settle_batch(self, life: Lifecycle) -> None:
        await self._ready(life)
        life.rpc.logs = [settled_log(life.descriptor, life.channel_id, 300, 300)]
        life.rpc.states[life.channel_id] = (300, DEPOSIT, 0)
        hashes = await settlement.settle_batch(
            life.store, [life.channel_id], account=PAYEE, rpc_url=RPC, http_client=life.rpc.client
        )
        assert len(hashes) == 1

    @pytest.mark.parametrize(
        ("state", "logged", "match"),
        [
            ((300, DEPOSIT, 0), 299, "below voucher amount"),
            ((299, DEPOSIT, 0), 300, "does not match settle receipt"),
        ],
    )
    async def test_rejects_inconsistent_results(
        self, life: Lifecycle, state: tuple[int, int, int], logged: int, match: str
    ) -> None:
        await self._ready(life)
        life.rpc.logs = [settled_log(life.descriptor, life.channel_id, logged, logged)]
        life.rpc.states[life.channel_id] = state
        with pytest.raises(VerificationFailedError, match=match):
            await settlement.settle(
                life.store, life.channel_id, account=PAYEE, rpc_url=RPC, http_client=life.rpc.client
            )

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

    async def test_checkpoint_failure_still_reports_the_settlement(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life)
        life.rpc.logs = [settled_log(life.descriptor, life.channel_id, 300, 300)]
        life.rpc.states[life.channel_id] = (300, DEPOSIT, 0)
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

    async def test_scheduled_checkpoint_failure_returns_the_hash(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life)
        channel = await life.channel()

        async def confirmed_unrecorded(*args: Any, **kwargs: Any) -> str:
            raise settlement.SettlementCheckpointError(tx_hash="0xabc", cause=RuntimeError())

        monkeypatch.setattr(settlement, "settle", confirmed_unrecorded)
        failures: list[settlement.SessionSettlementFailureContext] = []
        tx_hash = await settlement.maybe_settle_scheduled(
            channel=channel,
            schedule=ResolvedSettlementSchedule(units=1),
            store=life.store,
            account=PAYEE,
            rpc_url=RPC,
            on_session_settlement_failure=failures.append,
        )
        assert tx_hash == "0xabc" and len(failures) == 1
        assert (await life.channel()).scheduled_settlement_lease is None

    async def test_scheduled_settlement_needs_an_account(self, life: Lifecycle) -> None:
        await self._ready(life)
        with pytest.raises(ValueError, match="no account available"):
            await settlement.maybe_settle_scheduled(
                channel=await life.channel(),
                schedule=ResolvedSettlementSchedule(units=1),
                store=life.store,
                account=None,
                rpc_url=RPC,
            )

    async def test_scheduled_lease_failure_is_retryable(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life)

        async def broken(**kwargs: Any) -> str:
            raise RuntimeError("store down")

        monkeypatch.setattr(settlement, "claim_scheduled_settlement", broken)
        failures: list[settlement.SessionSettlementFailureContext] = []

        def boom(context: settlement.SessionSettlementFailureContext) -> None:
            failures.append(context)
            raise RuntimeError("observer errors are swallowed")

        with pytest.raises(settlement.SettlementLeaseError) as raised:
            await settlement.maybe_settle_scheduled(
                channel=await life.channel(),
                schedule=ResolvedSettlementSchedule(units=1),
                store=life.store,
                account=PAYEE,
                rpc_url=RPC,
                on_session_settlement_failure=boom,
            )
        assert len(failures) == 1
        assert settlement.ignore_retryable_settlement_failure(raised.value) is None

    async def test_scheduled_settlement_survives_a_failed_completion_mark(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await self._ready(life)

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
        tx_hash = await settlement.maybe_settle_scheduled(
            channel=await life.channel(),
            schedule=ResolvedSettlementSchedule(units=1),
            store=life.store,
            account=PAYEE,
            rpc_url=RPC,
            on_session_settlement=events.append,
        )
        assert tx_hash == "0xdef"
        assert [e.trigger for e in events] == ["scheduled"]
        assert (await life.channel()).scheduled_settlement_lease is None

    async def test_long_settlements_renew_their_lease(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        await self._ready(life)
        renewals: list[str] = []

        async def renew(**kwargs: Any) -> None:
            renewals.append(kwargs["lease_owner"])
            raise RuntimeError("renewal errors are ignored")

        async def slow(*args: Any, **kwargs: Any) -> str:
            await asyncio.sleep(0.05)
            return "0x01"

        monkeypatch.setattr(settlement, "renew_scheduled_settlement", renew)
        monkeypatch.setattr(settlement, "settle", slow)
        tx_hash = await settlement.maybe_settle_scheduled(
            channel=await life.channel(),
            schedule=ResolvedSettlementSchedule(units=1),
            store=life.store,
            account=PAYEE,
            rpc_url=RPC,
            lease_ms=20,
        )
        assert tx_hash == "0x01" and renewals

    def test_settlement_sender(self) -> None:
        check = settlement.assert_settlement_sender
        check(
            operation="settle",
            channel_id="0x1",
            operator=PAYER.address,
            payee=PAYEE.address,
            sender=PAYER.address,
        )
        with pytest.raises(ValueError, match="no account available"):
            check(
                operation="close",
                channel_id="0x1",
                operator=ZERO_ADDRESS,
                payee=PAYEE.address,
                sender=None,
            )
        with pytest.raises(BadRequestError, match="or operator"):
            check(
                operation="close",
                channel_id="0x1",
                operator=PAYER.address,
                payee=PAYEE.address,
                sender=SPONSOR.address,
            )

    @pytest.mark.parametrize(
        ("error", "retryable"),
        [
            (
                httpx.HTTPStatusError(
                    "x", request=httpx.Request("POST", RPC), response=httpx.Response(503)
                ),
                True,
            ),
            (
                httpx.HTTPStatusError(
                    "x", request=httpx.Request("POST", RPC), response=httpx.Response(429)
                ),
                True,
            ),
            (
                httpx.HTTPStatusError(
                    "x", request=httpx.Request("POST", RPC), response=httpx.Response(400)
                ),
                False,
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

    async def test_charge_maps_store_failures(self) -> None:
        store = from_store(MemoryStore())
        with pytest.raises(ChannelClosedError, match="not found"):
            await settlement.charge_session_channel(store, CHANNEL_ID, 1)

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
        charged = replace(
            ChannelState(
                channel_id=CHANNEL_ID,
                authorized_signer=PAYER.address,
                chain_id=CHAIN_ID,
                escrow_contract=ESCROW_ADDRESS,
                payer=PAYER.address,
                payee=PAYEE.address,
                token=CURRENCY,
                deposit=10,
                settled_on_chain=0,
                highest_voucher_amount=10,
                highest_voucher=None,
                spent=0,
                units=0,
                close_requested_at=0,
                finalized=False,
                created_at="t",
            ),
            spent=5,
            units=1,
        )

        async def charge(channel_id: str, amount: int) -> ChannelState:
            return charged

        async def no_settlement(channel: ChannelState) -> str | None:
            return None

        result = await settlement.apply_verified_http_accounting(
            receipt=receipt,
            request=request_state.RequestProbe("GET", httpx.Headers()),
            payload_action="voucher",
            request_amount=lambda: 5,
            charge=charge,
            settle_charged=no_settlement,
        )
        assert (result.spent, result.units, result.tx_hash) == ("5", 1, "0xopen")
        untouched = await settlement.apply_verified_http_accounting(
            receipt=receipt,
            request=request_state.RequestProbe("GET", httpx.Headers()),
            payload_action="topUp",
            request_amount=lambda: 5,
            charge=charge,
            settle_charged=no_settlement,
        )
        assert untouched is receipt


# --------------------------------------------------------------------------------------------
# Schedule leases
# --------------------------------------------------------------------------------------------


class TestScheduleLeases:
    async def test_lease_helpers_ignore_missing_channels_and_other_owners(
        self, life: Lifecycle
    ) -> None:
        store = life.store
        for helper in (mark_settlement_complete, release_scheduled_settlement):
            await helper(channel_id=life.channel_id, lease_owner="me", store=store)
        await renew_scheduled_settlement(channel_id=life.channel_id, lease_owner="me", store=store)
        assert await store.get_channel(life.channel_id) is None

        await life.open(300)
        await life.update(spent=300, units=3)
        owner = await claim_scheduled_settlement(
            channel_id=life.channel_id, schedule=ResolvedSettlementSchedule(units=1), store=store
        )
        assert owner is not None
        before = (await life.channel()).scheduled_settlement_lease
        await renew_scheduled_settlement(
            channel_id=life.channel_id, lease_owner="other", store=store
        )
        await release_scheduled_settlement(
            channel_id=life.channel_id, lease_owner="other", store=store
        )
        await mark_settlement_complete(channel_id=life.channel_id, lease_owner="other", store=store)
        assert (await life.channel()).scheduled_settlement_lease == before
        await release_scheduled_settlement(
            channel_id=life.channel_id, lease_owner=owner, store=store
        )
        assert (await life.channel()).scheduled_settlement_lease is None

    async def test_progress_without_a_parseable_timestamp(self, life: Lifecycle) -> None:
        await life.open(300)
        await life.update(spent=300, created_at="yesterday")
        progress = resolve_settlement_progress(await life.channel())
        assert progress is not None and progress.elapsed_ms is None


# --------------------------------------------------------------------------------------------
# The session method (Session.test.ts)
# --------------------------------------------------------------------------------------------


def authorize(challenge: Challenge, payload: dict[str, Any]) -> dict[str, str]:
    credential = Credential(challenge=challenge.to_echo(), payload=payload, source=SOURCE)
    return {"Authorization": credential.to_authorization()}


async def challenge_for(handler: Any, request: Request) -> Challenge:
    result = await handler(request)
    assert isinstance(result, PaymentRequired), result
    return Challenge.from_www_authenticate(result.challenge.headers["www-authenticate"])


class TestSessionMethod:
    def _server(self, life: Lifecycle, **options: Any) -> Mpp:
        method = tempo_server.session(
            account=PAYEE,
            currency=CURRENCY,
            rpc_url=RPC,
            http_client=life.rpc.client,
            store=life.raw,
            **options,
        )
        return Mpp(methods=[method], realm="api.test", secret_key="secret")

    async def test_chain_id_comes_from_the_rpc_once(self, life: Lifecycle) -> None:
        handler = self._server(life).session(amount="0.0001", unit_type="request")
        reads = len(life.rpc.methods("eth_chainId"))
        await challenge_for(handler, Request("GET", "http://api.test/paid"))
        challenge = await challenge_for(handler, Request("GET", "http://api.test/paid"))
        assert challenge.request["methodDetails"]["chainId"] == CHAIN_ID
        assert len(life.rpc.methods("eth_chainId")) == reads + 1

    async def test_opens_and_charges_through_the_engine(self, life: Lifecycle) -> None:
        handler = self._server(life, chain_id=CHAIN_ID).session(
            amount="0.0001", unit_type="request"
        )
        url = "http://api.test/paid"
        challenge = await challenge_for(handler, Request("GET", url))
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        result = await handler(
            Request("GET", url, headers=authorize(challenge, life.open_payload(100).to_wire()))
        )
        assert isinstance(result, PaymentVerified), result
        assert (await life.channel()).spent == 100

    async def test_adopts_the_engine_store(self, life: Lifecycle) -> None:
        # Mpp(store=...) reaches a session method configured without its own store.
        method = tempo_server.session(
            account=PAYEE, currency=CURRENCY, rpc_url=RPC, http_client=life.rpc.client
        )
        server = Mpp(methods=[method], realm="api.test", secret_key="secret", store=life.raw)
        handler = server.session(amount="0.0001", unit_type="request")
        url = "http://api.test/paid"
        challenge = await challenge_for(handler, Request("GET", url))
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        result = await handler(
            Request("GET", url, headers=authorize(challenge, life.open_payload(100).to_wire()))
        )
        assert isinstance(result, PaymentVerified), result
        assert (await life.channel()).spent == 100

    async def test_route_fee_payer_account_sponsors(self) -> None:
        # A route's fee-payer account co-signs the open its challenge advertised (mppx
        # resolveCredentialFeePayer), even on a method configured without one.
        life = await Lifecycle().build(fee_payer=True)
        handler = self._server(life, chain_id=CHAIN_ID).session(
            amount="0.0001", unit_type="request", fee_payer=SPONSOR
        )
        url = "http://api.test/paid"
        challenge = await challenge_for(handler, Request("GET", url))
        assert challenge.request["methodDetails"]["feePayer"] is True
        life.rpc.logs = [opened_log(life.descriptor, life.channel_id)]
        result = await handler(
            Request("GET", url, headers=authorize(challenge, life.open_payload(100).to_wire()))
        )
        assert isinstance(result, PaymentVerified), result
        assert life.rpc.sent[0].startswith("0x76")
        assert (await life.channel()).spent == 100

    async def test_scheduled_settlement_failure_keeps_the_request_served(
        self, life: Lifecycle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mpp.methods.tempo.session.server.schedule import SettlementSchedule

        await life.open(100)

        async def down(*args: Any, **kwargs: Any) -> str:
            raise httpx.ConnectError("node down")

        monkeypatch.setattr(chain, "settle_on_chain", down)
        handler = self._server(
            life, chain_id=CHAIN_ID, settlement_schedule=SettlementSchedule(units=1)
        ).session(amount="0.0001", unit_type="request")
        url = "http://api.test/paid"
        challenge = await challenge_for(handler, Request("GET", url))
        result = await handler(
            Request("GET", url, headers=authorize(challenge, life.voucher_payload(200).to_wire()))
        )
        assert isinstance(result, PaymentVerified), result
        assert result.receipt.to_payment_receipt()
        assert (await life.channel()).spent == 100

    async def test_needs_a_recipient(self) -> None:
        method = tempo_server.session(chain_id=CHAIN_ID, rpc_url=RPC, store=MemoryStore())
        handler = Mpp(methods=[method], realm="api.test", secret_key="s").session(
            amount="1", unit_type="request"
        )
        with pytest.raises(ValueError, match="needs a recipient"):
            await handler(Request("GET", "http://api.test/paid"))

    def test_reads_the_request_body(self) -> None:
        # A POST is content only when it has a body, so adapters must pass the body through.
        method = tempo_server.session(account=PAYEE, rpc_url=RPC, store=MemoryStore())
        assert method.needs_request_body
        handler = Mpp(methods=[method], realm="api.test", secret_key="s").session(
            amount="1", unit_type="request"
        )
        assert handler.needs_request_body

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


# --------------------------------------------------------------------------------------------
# Settlement and charging edges
# --------------------------------------------------------------------------------------------


class TestSettlementEdges:
    async def test_charge_reports_why_a_channel_cannot_pay(self, life: Lifecycle) -> None:
        await life.open(300)
        await life.update(finalized=True)
        with pytest.raises(ChannelClosedError, match="finalized"):
            await settlement.charge_session_channel(life.store, life.channel_id, 1)
        await life.update(finalized=False, close_requested_at=5)
        with pytest.raises(ChannelClosedError, match="pending close"):
            await settlement.charge_session_channel(life.store, life.channel_id, 1)
        await life.update(close_requested_at=0)
        with pytest.raises(InsufficientBalanceError, match="available 300"):
            await settlement.charge_session_channel(life.store, life.channel_id, 301)

    def test_accounting_applies_only_to_content_requests(self) -> None:
        apply = settlement.should_apply_verified_http_accounting
        get = request_state.RequestProbe("GET", httpx.Headers())
        assert apply(request=get, payload_action="open")
        assert not apply(request=None, payload_action="voucher")
        assert not apply(request=get, payload_action="close")

    async def test_settle_replaces_an_expired_credit_floor(self, life: Lifecycle) -> None:
        from mpp.methods.tempo.session.server.store import PendingSettlement

        await life.open(300)
        await life.update(spent=300, pending_settlement=PendingSettlement(amount=900, expires_at=1))
        life.rpc.logs = [settled_log(life.descriptor, life.channel_id, 300, 300)]
        life.rpc.states[life.channel_id] = (300, DEPOSIT, 0)
        await settlement.settle(
            life.store, life.channel_id, account=PAYEE, rpc_url=RPC, http_client=life.rpc.client
        )
        # The expired floor was dropped rather than kept at 900.
        assert (await life.channel()).pending_settlement is None

    def test_resolve_channel_store(self) -> None:
        raw = MemoryStore()
        wrapped = settlement.resolve_channel_store(raw)
        assert isinstance(wrapped, StoreChannelStore)
        assert settlement.resolve_channel_store(wrapped) is wrapped


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


class TestChannelStoreEdges:
    async def test_non_atomic_store_sets_and_deletes(self, life: Lifecycle) -> None:
        from mpp.methods.tempo.session.server import store as store_module

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
        with pytest.raises(ValueError, match="needs a value"):
            await channel_store.update_channel_result(
                life.channel_id, lambda c: store_module.StoreChange("set", None)
            )
        waiter = channel_store.wait_for_update(life.channel_id)
        done = channel_store.wait_for_update(life.channel_id)
        done.cancel()
        assert (
            await channel_store.update_channel_result(
                life.channel_id, lambda c: store_module.StoreChange("delete", "gone")
            )
            == "gone"
        )
        await waiter
        assert raw.data == {}

    async def test_cas_store_rejects_a_set_without_value(self, life: Lifecycle) -> None:
        from mpp.methods.tempo.session.server import store as store_module

        await life.open(300)
        with pytest.raises(ValueError, match="needs a value"):
            await life.store.update_channel_result(
                life.channel_id, lambda c: store_module.StoreChange("set", None)
            )

    async def test_apply_change_on_a_custom_channel_store(self, life: Lifecycle) -> None:
        from mpp.methods.tempo.session.server import store as store_module

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
        from mpp.methods.tempo.session.server import store as store_module

        await life.open(300)
        record = store_module.channel_state_to_json(await life.channel())
        assert store_module.channel_state_from_json(record) == await life.channel()
        bare = replace(
            await life.channel(),
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
        for broken in (
            {**record, "deposit": True},
            {**record, "deposit": 1.5},
            {**record, "deposit": None},
            {**record, "backend": "magic"},
            {**record, "highestVoucher": "0x"},
            {
                **record,
                "idempotencyMarkers": {
                    "charge:k": {"amount": "1", "expiresAt": "1", "outcome": "lost"}
                },
            },
        ):
            with pytest.raises((ValueError, TypeError)):
                store_module.channel_state_from_json(broken)

    def test_settleable_voucher_prefers_the_largest_within_spent(self, life: Lifecycle) -> None:
        from mpp.methods.tempo.session.server.store import (
            RetainedVoucher,
            resolve_settleable_voucher,
        )

        state = ChannelState(
            channel_id=CHANNEL_ID,
            authorized_signer=PAYER.address,
            chain_id=CHAIN_ID,
            escrow_contract=ESCROW_ADDRESS,
            payer=PAYER.address,
            payee=PAYEE.address,
            token=CURRENCY,
            deposit=1_000,
            settled_on_chain=100,
            highest_voucher_amount=0,
            highest_voucher=None,
            spent=500,
            units=0,
            close_requested_at=0,
            finalized=False,
            created_at="t",
            retained_vouchers=(
                RetainedVoucher(100, "0x01"),
                RetainedVoucher(400, "0x04"),
                RetainedVoucher(300, "0x03"),
                RetainedVoucher(600, "0x06"),
            ),
        )
        voucher = resolve_settleable_voucher(state)
        assert voucher is not None and (voucher.cumulative_amount, voucher.signature) == (
            400,
            "0x04",
        )

    def test_close_helpers_on_missing_or_finalized_channels(self, life: Lifecycle) -> None:
        from mpp.methods.tempo.session.server.store import (
            finalize_closed_channel_state,
            mark_pending_close,
        )

        assert (
            finalize_closed_channel_state(
                capture_amount=1,
                channel_id=CHANNEL_ID,
                cumulative_amount=1,
                current=None,
                signature="0x",
            )
            is None
        )
        state = ChannelState(
            channel_id=CHANNEL_ID,
            authorized_signer=PAYER.address,
            chain_id=CHAIN_ID,
            escrow_contract=ESCROW_ADDRESS,
            payer=PAYER.address,
            payee=PAYEE.address,
            token=CURRENCY,
            deposit=1_000,
            settled_on_chain=0,
            highest_voucher_amount=0,
            highest_voucher=None,
            spent=0,
            units=0,
            close_requested_at=0,
            finalized=True,
            created_at="t",
        )
        with pytest.raises(ChannelClosedError, match="already finalized"):
            mark_pending_close(
                close_requested_at=1,
                cumulative_amount=1,
                current=state,
                on_chain_deposit=1_000,
                on_chain_settled=0,
            )

    async def test_credit_requires_an_idempotency_key(self, life: Lifecycle) -> None:
        await life.open(300)
        with pytest.raises(ValueError, match="idempotency_key"):
            await session.credit(life.store, life.channel_id, 1, idempotency_key=None)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------
# Engine hooks used by the session method
# --------------------------------------------------------------------------------------------


class TestEngineHooks:
    def test_server_method_checks_its_hooks(self) -> None:
        from mpp.methods.tempo.session.protocol import definition
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

    def test_bare_post_without_url_is_management(self) -> None:
        probe = request_state.RequestProbe("POST", httpx.Headers())
        assert not request_state.is_session_content_request(probe)


class TestSessionOverMcp:
    """An MCP tool call is a billable content request (mppx's MCP transports set hasBody)."""

    async def test_each_tool_call_is_charged_and_a_replayed_voucher_rejected(
        self, life: Lifecycle
    ) -> None:
        from mpp.extensions.mcp import MCPCredential, verify_or_challenge
        from mpp.extensions.mcp.errors import PaymentVerificationError

        method = tempo_server.session(
            account=PAYEE,
            chain_id=CHAIN_ID,
            currency=CURRENCY,
            rpc_url=RPC,
            http_client=life.rpc.client,
            store=life.raw,
        )
        handler = Mpp(methods=[method], realm="api.test", secret_key="secret").session(
            amount="0.0001", unit_type="request"
        )

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
        assert (await life.channel()).spent == 100
        assert isinstance(await call(life.voucher_payload(200)), tuple)
        assert (await life.channel()).spent == 200
        assert isinstance(await call(life.voucher_payload(300)), tuple)
        channel = await life.channel()
        assert (channel.spent, channel.units) == (300, 3)

        with pytest.raises(PaymentVerificationError):
            await call(life.voucher_payload(300))
        assert (await life.channel()).spent == 300


class RefusingCasStore(DictStore):
    """A store whose compare_and_set is refused, like Redis denying EVAL."""

    __slots__ = ("attempts",)

    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    async def put_if_absent(self, key: str, value: Any) -> bool:
        return self.data.setdefault(key, value) is value

    async def compare_and_set(self, key: str, expected: Any, value: Any) -> bool:
        self.attempts += 1
        raise NotImplementedError("EVAL denied")


class WriteRefusingCasStore(DictStore):
    """A store whose compare_and_set refuses only writes, like Redis without KEEPTTL."""

    async def put_if_absent(self, key: str, value: Any) -> bool:
        return self.data.setdefault(key, value) is value

    async def compare_and_set(self, key: str, expected: Any, value: Any) -> bool:
        if value is not None:
            raise NotImplementedError("SET KEEPTTL: syntax error")
        if self.data.get(key) != expected:
            return False
        self.data.pop(key, None)
        return True


class TestChannelStoreCasRefused:
    async def test_open_fails_before_broadcast_when_compare_and_set_is_refused(
        self, life: Lifecycle
    ) -> None:
        from mpp.methods.tempo.session.server import store as store_module

        raw = RefusingCasStore()
        channel_store = store_module.StoreChannelStore(raw)
        assert channel_store.atomic
        life.store = channel_store
        with pytest.raises(NotImplementedError, match="refused compare_and_set"):
            await life.open(300)
        # Nothing was broadcast and nothing was stored: the payer's deposit never moved.
        assert not life.rpc.sent
        assert raw.attempts == 1 and not raw.data
        assert channel_store.atomic

    async def test_top_up_fails_before_broadcast_when_compare_and_set_is_refused(
        self, life: Lifecycle
    ) -> None:
        from mpp.methods.tempo.session.server import store as store_module

        await life.open(300)
        sent = len(life.rpc.sent)
        raw = RefusingCasStore()
        raw.data.update(life.raw._data)  # pyright: ignore[reportPrivateUsage]
        payload = await life.top_up_payload(500)
        with pytest.raises(NotImplementedError, match="refused compare_and_set"):
            await verification.broadcast_credential_payload(
                life.context(payload, store=store_module.StoreChannelStore(raw))
            )
        assert len(life.rpc.sent) == sent

    async def test_updates_raise_instead_of_dropping_atomicity(self, life: Lifecycle) -> None:
        from mpp.methods.tempo.session.server import store as store_module

        await life.open(300)
        raw = RefusingCasStore()
        raw.data.update(life.raw._data)  # pyright: ignore[reportPrivateUsage]
        channel_store = store_module.StoreChannelStore(raw)
        for _ in range(2):
            with pytest.raises(NotImplementedError, match="refused compare_and_set"):
                await channel_store.update_channel(
                    life.channel_id, lambda c: replace(c, spent=10) if c else c
                )
        assert raw.attempts == 2 and channel_store.atomic
        assert (await channel_store.get_channel(life.channel_id)).spent == 0  # type: ignore[union-attr]

    async def test_probe_exercises_the_write_a_channel_update_makes(self, life: Lifecycle) -> None:
        from mpp.methods.tempo.session.server import store as store_module

        # Like Redis without KEEPTTL: a CAS that only reads or deletes succeeds, a write fails.
        raw = WriteRefusingCasStore()
        channel_store = store_module.StoreChannelStore(raw)
        life.store = channel_store
        with pytest.raises(NotImplementedError, match="refused compare_and_set"):
            await life.open(300)
        assert not life.rpc.sent and not raw.data

    async def test_probe_runs_once_and_changes_nothing(self, life: Lifecycle) -> None:
        await life.open(300)
        before = dict(life.raw._data)  # pyright: ignore[reportPrivateUsage]
        await check_atomic_update(life.store, life.channel_id)
        await check_atomic_update(life.store, "0x" + "ab" * 32)
        assert life.raw._data == before  # pyright: ignore[reportPrivateUsage]


class BytesCasStore(DictStore):
    """A store that keeps values as bytes and compares expected values as given."""

    async def put_if_absent(self, key: str, value: Any) -> bool:
        return self.data.setdefault(key, value) is value

    async def get(self, key: str) -> Any:
        return self.data.get(key)

    async def compare_and_set(self, key: str, expected: Any, value: Any) -> bool:
        if self.data.get(key) != expected:
            return False
        if value is None:
            self.data.pop(key, None)
        else:
            self.data[key] = value.encode() if isinstance(value, str) else value
        return True


class DeleteRefusingCasStore(BytesCasStore):
    """A store that writes but refuses deletes, like a Redis ACL that denies DEL."""

    async def compare_and_set(self, key: str, expected: Any, value: Any) -> bool:
        if value is None:
            raise NotImplementedError("DEL denied")
        return await super().compare_and_set(key, expected, value)


class TestChannelStoreProbeStores:
    async def test_bytes_store_passes_the_probe_and_leaves_no_key(self) -> None:
        from mpp.methods.tempo.session.server import store as store_module

        raw = BytesCasStore()
        channel_store = store_module.StoreChannelStore(raw)
        await channel_store.check_atomic_update("0x" + "ab" * 32)
        assert not raw.data

    async def test_failed_cleanup_leaves_one_key_per_adapter(self) -> None:
        from mpp.methods.tempo.session.server import store as store_module

        raw = DeleteRefusingCasStore()
        for _ in range(3):
            await store_module.StoreChannelStore(raw).check_atomic_update("0x" + "ab" * 32)
        assert len(raw.data) == 3
        assert all(key.startswith("mpp:session:cas-probe:") for key in raw.data)

    async def test_concurrent_probes_on_one_adapter_never_refuse(self) -> None:
        from mpp.methods.tempo.session.server import store as store_module

        raw = BytesCasStore()
        channel_store = store_module.StoreChannelStore(raw)
        await asyncio.gather(
            *(channel_store.check_atomic_update("0x" + "ab" * 32) for _ in range(20))
        )
        assert not raw.data

    async def test_leftover_probe_write_does_not_read_as_refusal(self) -> None:
        from mpp.methods.tempo.session.server import store as store_module

        raw = BytesCasStore()
        channel_store = store_module.StoreChannelStore(raw)
        # An earlier probe on this adapter wrote its key, then was interrupted.
        raw.data[channel_store._cas_probe_key] = b"1"  # pyright: ignore[reportPrivateUsage]
        await channel_store.check_atomic_update("0x" + "ab" * 32)
        assert not raw.data


class TestFromStoreCache:
    def test_released_store_and_adapter_are_collected(self) -> None:
        import gc
        import weakref as _weakref

        from mpp.methods.tempo.session.server import store as store_module
        from mpp.store import MemoryStore

        raw = MemoryStore()
        adapter = store_module.from_store(raw)
        assert store_module.from_store(raw) is adapter
        ref = _weakref.ref(raw)
        del raw, adapter
        gc.collect()
        assert ref() is None
