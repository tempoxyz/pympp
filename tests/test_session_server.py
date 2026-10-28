"""Session server: verification, settlement, close supervision and the session method.

Ports the important cases of mppx `server/CredentialVerification.test.ts`, `Settlement.test.ts`,
`CloseSupervisor.test.ts` and `Session.test.ts` with the chain mocked.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.errors import BadRequestError, VerificationFailedError
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo.session import abi, chain
from mpp.methods.tempo.session.channel import compute_channel_id
from mpp.methods.tempo.session.protocol import (
    ESCROW_ADDRESS,
    ZERO_ADDRESS,
    ChannelDescriptor,
    ClosePayload,
    OpenPayload,
    TopUpPayload,
    VoucherPayload,
)
from mpp.methods.tempo.session.server import (
    SessionPaymentReceipt,
    charge,
    credit,
    request_state,
    settle,
    settlement,
    supervise_closes,
)
from mpp.methods.tempo.session.server.schedule import (
    ResolvedSettlementSchedule,
    SettlementSchedule,
)
from mpp.methods.tempo.session.server.settlement import (
    SessionSettlementContext,
    SettlementLeaseError,
    charge_session_channel,
    ignore_retryable_settlement_failure,
    maybe_settle_scheduled,
)
from mpp.methods.tempo.session.server.store import (
    AmountExceedsDepositError,
    ChannelClosedError,
    ChannelNotFoundError,
    ChannelState,
    DeltaTooSmallError,
    IdempotencyKeyConflictError,
    InsufficientBalanceError,
    InvalidSignatureError,
    StoreChannelStore,
    from_store,
    open_channel_state,
)
from mpp.methods.tempo.session.server.verification import (
    CredentialContext,
    broadcast_credential_payload,
    require_session_credential_payload,
    validate_credential_payload,
)
from mpp.methods.tempo.session.voucher import sign_close_authorization, sign_voucher
from mpp.server import Mpp, PaymentRequired, PaymentVerified, Request, Response
from mpp.store import MemoryStore

CHAIN_ID = 1337
CURRENCY = "0x20c0000000000000000000000000000000000000"
PAYER = TempoAccount.from_key("0x" + "11" * 32)
PAYEE = TempoAccount.from_key("0x" + "22" * 32)
STRANGER = TempoAccount.from_key("0x" + "33" * 32)
SOURCE = f"did:pkh:eip155:{CHAIN_ID}:{PAYER.address}"
DEPOSIT = 10_000
SECRET = "session-server-secret"
REALM = "api.test"


def make_descriptor(**overrides: str) -> ChannelDescriptor:
    fields: dict[str, str] = {
        "payer": PAYER.address,
        "payee": PAYEE.address,
        "operator": ZERO_ADDRESS,
        "token": CURRENCY,
        "salt": "0x" + "01" * 32,
        "authorized_signer": ZERO_ADDRESS,
        "expiring_nonce_hash": "0x" + "ab" * 32,
    }
    fields.update(overrides)
    return ChannelDescriptor(**fields)


DESCRIPTOR = make_descriptor()
CHANNEL_ID = compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID, escrow=ESCROW_ADDRESS)


def on_chain(deposit: int = DEPOSIT, settled: int = 0, close: int = 0) -> chain.ChannelState:
    return chain.ChannelState(settled=settled, deposit=deposit, close_requested_at=close)


def sign(amount: int, account: TempoAccount = PAYER, channel_id: str = CHANNEL_ID) -> str:
    return sign_voucher(account, channel_id=channel_id, cumulative_amount=amount, chain_id=CHAIN_ID)


def session_request(amount: str = "100", **details: Any) -> dict[str, Any]:
    return {
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
    }


def make_challenge(amount: str = "100", **details: Any) -> Challenge:
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    return Challenge(
        id="challenge-1",
        method="tempo",
        intent="session",
        request=session_request(amount, **details),
        expires=expires,
    )


async def seeded_store(
    *, spent: int = 0, highest: int = 0, deposit: int = DEPOSIT, settled: int = 0
) -> StoreChannelStore:
    """A channel store holding the test channel, opened with a voucher of `highest`."""
    channel_store = from_store(MemoryStore())
    initial = highest or 100

    def update(current: ChannelState | None) -> ChannelState:
        state = open_channel_state(
            authorized_signer=PAYER.address,
            chain_id=CHAIN_ID,
            channel_id=CHANNEL_ID,
            current=current,
            descriptor=DESCRIPTOR,
            escrow=ESCROW_ADDRESS,
            expiring_nonce_hash=DESCRIPTOR.expiring_nonce_hash,
            cumulative_amount=initial,
            signature=sign(initial),
            state=on_chain(deposit, settled),
        )
        return replace(state, spent=spent, units=spent // 100)

    await channel_store.update_channel(CHANNEL_ID, update)
    return channel_store


def voucher_payload(
    amount: int, *, signature: str | None = None, descriptor: ChannelDescriptor = DESCRIPTOR
) -> VoucherPayload:
    channel_id = compute_channel_id(descriptor, chain_id=CHAIN_ID, escrow=ESCROW_ADDRESS)
    return VoucherPayload.model_validate(
        {
            "action": "voucher",
            "channelId": channel_id,
            "descriptor": descriptor.to_wire(),
            "cumulativeAmount": str(amount),
            "signature": signature or sign(amount, channel_id=channel_id),
        }
    )


def context(channel_store: StoreChannelStore, payload: Any, **overrides: Any) -> CredentialContext:
    fields: dict[str, Any] = {
        "challenge": make_challenge(),
        "payload": payload,
        "chain_id": CHAIN_ID,
        "escrow": ESCROW_ADDRESS,
        "rpc_url": "http://rpc.invalid",
        "store": channel_store,
        "account": PAYEE,
        "credential_source": SOURCE,
    }
    fields.update(overrides)
    return CredentialContext(**fields)


@pytest.fixture
def chain_state(monkeypatch: pytest.MonkeyPatch) -> list[chain.ChannelState]:
    """The on-chain state `chain.get_channel_state` returns (last element); reads are counted."""
    states = [on_chain()]
    reads: list[str] = []

    async def get_channel_state(rpc_url: str, channel_id: str, **kwargs: Any) -> chain.ChannelState:
        reads.append(channel_id)
        return states[-1]

    monkeypatch.setattr(chain, "get_channel_state", get_channel_state)
    return states


# --------------------------------------------------------------------------------------------
# Voucher verification (CredentialVerification.test.ts)
# --------------------------------------------------------------------------------------------


async def test_voucher_advances_highest_and_returns_receipt(
    chain_state: list[chain.ChannelState],
) -> None:
    channel_store = await seeded_store(spent=100, highest=100)
    receipt = await broadcast_credential_payload(context(channel_store, voucher_payload(300)))
    assert receipt.accepted_cumulative == "300"
    assert receipt.spent == "100"
    assert receipt.channel_id == CHANNEL_ID
    assert receipt.challenge_id == "challenge-1"
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.highest_voucher_amount == 300
    assert channel.on_chain_verified_at is not None


async def test_replayed_voucher_needs_new_funds_for_content(
    chain_state: list[chain.ChannelState],
) -> None:
    channel_store = await seeded_store(spent=100, highest=200)
    with pytest.raises(DeltaTooSmallError):
        await broadcast_credential_payload(
            context(channel_store, voucher_payload(200), require_voucher_advance=True)
        )
    # A management request may resend the accepted voucher: nothing changes.
    receipt = await broadcast_credential_payload(context(channel_store, voucher_payload(200)))
    assert receipt.accepted_cumulative == "200"


async def test_stale_voucher_is_rejected(chain_state: list[chain.ChannelState]) -> None:
    channel_store = await seeded_store(highest=500)
    with pytest.raises(VerificationFailedError, match="strictly greater"):
        await broadcast_credential_payload(context(channel_store, voucher_payload(400)))


async def test_voucher_above_deposit_is_rejected(chain_state: list[chain.ChannelState]) -> None:
    channel_store = await seeded_store()
    with pytest.raises(AmountExceedsDepositError):
        await broadcast_credential_payload(context(channel_store, voucher_payload(DEPOSIT + 1)))


async def test_voucher_at_or_below_settled_is_rejected(
    chain_state: list[chain.ChannelState],
) -> None:
    channel_store = await seeded_store(highest=100)
    chain_state.append(on_chain(settled=500))
    with pytest.raises(VerificationFailedError, match="settled"):
        await broadcast_credential_payload(context(channel_store, voucher_payload(500)))


async def test_voucher_below_min_delta_is_rejected(
    chain_state: list[chain.ChannelState],
) -> None:
    channel_store = await seeded_store(highest=100)
    with pytest.raises(DeltaTooSmallError, match="below minimum 50"):
        await broadcast_credential_payload(
            context(channel_store, voucher_payload(149), min_voucher_delta=50)
        )
    receipt = await broadcast_credential_payload(
        context(channel_store, voucher_payload(150), min_voucher_delta=50)
    )
    assert receipt.accepted_cumulative == "150"


async def test_voucher_from_wrong_signer_is_rejected(
    chain_state: list[chain.ChannelState],
) -> None:
    channel_store = await seeded_store()
    payload = voucher_payload(300, signature=sign(300, STRANGER))
    with pytest.raises(InvalidSignatureError):
        await broadcast_credential_payload(context(channel_store, payload))


async def test_descriptor_mismatch_is_rejected(chain_state: list[chain.ChannelState]) -> None:
    channel_store = await seeded_store()
    # A descriptor whose channel ID differs from the credential's channel.
    other = make_descriptor(salt="0x" + "02" * 32)
    payload = voucher_payload(300)
    tampered = VoucherPayload.model_validate({**payload.to_wire(), "descriptor": other.to_wire()})
    with pytest.raises(VerificationFailedError, match="does not match channelId"):
        await broadcast_credential_payload(context(channel_store, tampered))
    # A valid descriptor for an unknown channel.
    with pytest.raises(ChannelNotFoundError):
        await broadcast_credential_payload(
            context(channel_store, voucher_payload(300, descriptor=other))
        )
    # A descriptor paying someone else.
    elsewhere = make_descriptor(payee=STRANGER.address)
    with pytest.raises(VerificationFailedError, match="payee"):
        await broadcast_credential_payload(
            context(channel_store, voucher_payload(300, descriptor=elsewhere))
        )


async def test_credential_source_must_be_payer_or_signer(
    chain_state: list[chain.ChannelState],
) -> None:
    channel_store = await seeded_store()
    stranger = f"did:pkh:eip155:{CHAIN_ID}:{STRANGER.address}"
    with pytest.raises(VerificationFailedError, match="source"):
        await broadcast_credential_payload(
            context(channel_store, voucher_payload(300), credential_source=stranger)
        )
    with pytest.raises(VerificationFailedError, match="source"):
        await broadcast_credential_payload(
            context(channel_store, voucher_payload(300), credential_source=None)
        )


async def test_pending_close_on_chain_rejects_voucher_and_is_recorded(
    chain_state: list[chain.ChannelState], monkeypatch: pytest.MonkeyPatch
) -> None:
    channel_store = await seeded_store(spent=100, highest=100)
    chain_state.append(on_chain(close=1_700_000_000))
    settled: list[str] = []

    async def fake_settle(*args: Any, **kwargs: Any) -> str:
        settled.append("settle")
        return "0x" + "ee" * 32

    monkeypatch.setattr(settlement, "settle", fake_settle)
    with pytest.raises(ChannelClosedError, match="pending close"):
        await broadcast_credential_payload(context(channel_store, voucher_payload(300)))
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.close_requested_at == 1_700_000_000
    # The accepted spend is settled while the payee still can.
    assert settled == ["settle"]
    with pytest.raises(ChannelClosedError):
        await charge_session_channel(channel_store, CHANNEL_ID, 1)


async def test_finalized_channel_rejects_voucher(chain_state: list[chain.ChannelState]) -> None:
    channel_store = await seeded_store()
    await channel_store.update_channel(CHANNEL_ID, lambda c: replace(c, finalized=True) if c else c)
    with pytest.raises(ChannelClosedError, match="finalized"):
        await broadcast_credential_payload(context(channel_store, voucher_payload(300)))


async def test_validation_uses_cached_chain_state_within_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel_store = await seeded_store()
    reads: list[str] = []

    async def get_channel_state(rpc_url: str, channel_id: str, **kwargs: Any) -> chain.ChannelState:
        reads.append(channel_id)
        return on_chain()

    monkeypatch.setattr(chain, "get_channel_state", get_channel_state)
    verified: dict[str, int] = {}
    for amount in (200, 300):
        await validate_credential_payload(
            context(channel_store, voucher_payload(amount), last_on_chain_verified=verified)
        )
    assert len(reads) == 1
    # Acceptance always reads chain state first.
    await broadcast_credential_payload(
        context(channel_store, voucher_payload(300), last_on_chain_verified=verified)
    )
    assert len(reads) == 2


async def test_validate_allows_pending_close_before_broadcast(
    chain_state: list[chain.ChannelState],
) -> None:
    channel_store = await seeded_store()
    chain_state.append(on_chain(close=5))
    with pytest.raises(ChannelClosedError):
        await validate_credential_payload(context(channel_store, voucher_payload(300)))
    result = await validate_credential_payload(
        context(channel_store, voucher_payload(300), allow_pending_close=True)
    )
    assert result.action == "voucher"


async def test_concurrent_vouchers_never_lose_the_highest(
    chain_state: list[chain.ChannelState],
) -> None:
    channel_store = await seeded_store()
    amounts = list(range(200, 2_000, 100))
    results = await asyncio.gather(
        *(
            broadcast_credential_payload(context(channel_store, voucher_payload(a)))
            for a in amounts
        ),
        return_exceptions=True,
    )
    assert all(
        not isinstance(r, Exception) or isinstance(r, VerificationFailedError) for r in results
    )
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.highest_voucher_amount == amounts[-1]


# --------------------------------------------------------------------------------------------
# Payload reading
# --------------------------------------------------------------------------------------------


def test_payload_requires_raw_amounts_and_a_descriptor() -> None:
    wire = voucher_payload(300).to_wire()
    assert require_session_credential_payload(wire).action == "voucher"
    with pytest.raises(VerificationFailedError, match="cumulativeAmount"):
        require_session_credential_payload({**wire, "cumulativeAmount": "1.5"})
    with pytest.raises(VerificationFailedError, match="descriptor required"):
        require_session_credential_payload({k: v for k, v in wire.items() if k != "descriptor"})
    with pytest.raises(VerificationFailedError, match="descriptor.salt"):
        require_session_credential_payload(
            {**wire, "descriptor": {**wire["descriptor"], "salt": "0x12"}}
        )
    with pytest.raises(VerificationFailedError, match="action"):
        require_session_credential_payload({**wire, "action": "pay"})
    upper = require_session_credential_payload(
        {**wire, "channelId": CHANNEL_ID.upper().replace("0X", "0x")}
    )
    assert upper.channel_id == CHANNEL_ID.lower()


# --------------------------------------------------------------------------------------------
# Open and top-up
# --------------------------------------------------------------------------------------------


def open_payload(amount: int = 100) -> Any:
    return OpenPayload.model_validate(
        {
            "action": "open",
            "type": "transaction",
            "channelId": CHANNEL_ID,
            "transaction": "0x76",
            "signature": sign(amount),
            "descriptor": DESCRIPTOR.to_wire(),
            "cumulativeAmount": str(amount),
        }
    )


def fake_broadcast_open(
    monkeypatch: pytest.MonkeyPatch,
    *,
    deposit: int = DEPOSIT,
    descriptor: ChannelDescriptor = DESCRIPTOR,
) -> list[chain.ValidatedOpenTransaction]:
    prepared: list[chain.ValidatedOpenTransaction] = []

    async def broadcast_open_transaction(rpc_url: str, **kwargs: Any) -> chain.BroadcastOpenResult:
        validated = chain.ValidatedOpenTransaction(
            descriptor=descriptor,
            expiring_nonce_hash=descriptor.expiring_nonce_hash,
            open_deposit=deposit,
            transaction=None,  # type: ignore[arg-type]
        )
        kwargs["before_broadcast"](validated)
        prepared.append(validated)
        return chain.BroadcastOpenResult(
            tx_hash="0x" + "aa" * 32,
            descriptor=descriptor,
            state=on_chain(deposit),
            expiring_nonce_hash=descriptor.expiring_nonce_hash,
            open_deposit=deposit,
        )

    monkeypatch.setattr(chain, "broadcast_open_transaction", broadcast_open_transaction)
    return prepared


async def test_open_records_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_broadcast_open(monkeypatch)
    channel_store = from_store(MemoryStore())
    receipt = await broadcast_credential_payload(context(channel_store, open_payload(100)))
    assert receipt.tx_hash == "0x" + "aa" * 32
    assert receipt.accepted_cumulative == "100"
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.deposit == DEPOSIT and channel.payer == PAYER.address


async def test_open_must_cover_request_and_stay_within_deposit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel_store = from_store(MemoryStore())
    fake_broadcast_open(monkeypatch)
    with pytest.raises(VerificationFailedError, match="less than request amount"):
        await broadcast_credential_payload(context(channel_store, open_payload(99)))
    fake_broadcast_open(monkeypatch, deposit=150)
    with pytest.raises(AmountExceedsDepositError):
        await broadcast_credential_payload(context(channel_store, open_payload(200)))
    assert await channel_store.get_channel(CHANNEL_ID) is None


async def test_top_up_merges_new_deposit(monkeypatch: pytest.MonkeyPatch) -> None:
    channel_store = await seeded_store(spent=100, highest=100)

    async def broadcast_top_up_transaction(
        rpc_url: str, **kwargs: Any
    ) -> chain.BroadcastTopUpResult:
        assert kwargs["additional_deposit"] == 5_000
        return chain.BroadcastTopUpResult(
            tx_hash="0x" + "bb" * 32, new_deposit=DEPOSIT + 5_000, state=on_chain(DEPOSIT + 5_000)
        )

    monkeypatch.setattr(chain, "broadcast_top_up_transaction", broadcast_top_up_transaction)
    payload = TopUpPayload.model_validate(
        {
            "action": "topUp",
            "type": "transaction",
            "channelId": CHANNEL_ID,
            "transaction": "0x76",
            "descriptor": DESCRIPTOR.to_wire(),
            "additionalDeposit": "5000",
        }
    )
    receipt = await broadcast_credential_payload(context(channel_store, payload))
    assert receipt.tx_hash == "0x" + "bb" * 32
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.deposit == DEPOSIT + 5_000 and channel.spent == 100


# --------------------------------------------------------------------------------------------
# Close
# --------------------------------------------------------------------------------------------


def close_payload(amount: int, *, close_signer: TempoAccount = PAYER) -> ClosePayload:
    return ClosePayload.model_validate(
        {
            "action": "close",
            "channelId": CHANNEL_ID,
            "descriptor": DESCRIPTOR.to_wire(),
            "cumulativeAmount": str(amount),
            "signature": sign(amount),
            "closeSignature": sign_close_authorization(
                close_signer, channel_id=CHANNEL_ID, cumulative_amount=amount, chain_id=CHAIN_ID
            ),
        }
    )


class FakeClose:
    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, *, fail: BaseException | None = None
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail = fail
        self.send = True
        monkeypatch.setattr(chain, "close_on_chain", self.close_on_chain)
        monkeypatch.setattr(chain, "wait_for_successful_receipt", self.wait)
        monkeypatch.setattr(chain, "get_channel_event", self.event)

    async def close_on_chain(
        self,
        rpc_url: str,
        account: Any,
        descriptor: Any,
        cumulative: int,
        capture: int,
        signature: str,
        **kwargs: Any,
    ) -> str:
        self.calls.append({"cumulative": cumulative, "capture": capture, **kwargs})
        client = kwargs.get("client")
        if self.send and client is not None:
            # Record a send attempt through the tracked client.
            with contextlib.suppress(httpx.HTTPError):
                await client.post("http://rpc.invalid", json={"method": "eth_sendRawTransaction"})
        if self.fail is not None:
            raise self.fail
        return "0x" + "cc" * 32

    async def wait(self, rpc_url: str, tx_hash: str, **kwargs: Any) -> dict[str, Any]:
        return {"transactionHash": tx_hash, "blockNumber": "0x10", "logs": []}

    def event(self, receipt: Any, name: str, channel_id: str, **kwargs: Any) -> dict[str, Any]:
        capture = self.calls[-1]["capture"]
        return {
            "channelId": channel_id,
            "settledToPayee": capture,
            "refundedToPayer": DEPOSIT - capture,
        }


async def test_close_captures_spend_and_finalizes(
    chain_state: list[chain.ChannelState], monkeypatch: pytest.MonkeyPatch
) -> None:
    channel_store = await seeded_store(spent=700, highest=900)
    close = FakeClose(monkeypatch)
    settlements: list[SessionSettlementContext] = []
    receipt = await broadcast_credential_payload(
        context(channel_store, close_payload(900), on_session_settlement=settlements.append)
    )
    # The close captures what was spent, not the whole voucher.
    assert close.calls[0]["capture"] == 700 and close.calls[0]["cumulative"] == 900
    assert receipt.tx_hash == "0x" + "cc" * 32 and receipt.accepted_cumulative == "900"
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.finalized and channel.settled_on_chain == 700
    assert [(s.trigger, s.amount, s.delta) for s in settlements] == [("close", 700, 700)]


async def test_close_capture_is_at_least_settled(
    chain_state: list[chain.ChannelState], monkeypatch: pytest.MonkeyPatch
) -> None:
    channel_store = await seeded_store(spent=300, highest=900, settled=500)
    chain_state.append(on_chain(settled=500))
    close = FakeClose(monkeypatch)
    await broadcast_credential_payload(context(channel_store, close_payload(900)))
    assert close.calls[0]["capture"] == 500


async def test_close_below_spend_or_with_bad_authorization_is_rejected(
    chain_state: list[chain.ChannelState], monkeypatch: pytest.MonkeyPatch
) -> None:
    channel_store = await seeded_store(spent=700, highest=900)
    FakeClose(monkeypatch)
    with pytest.raises(VerificationFailedError, match="spent"):
        await broadcast_credential_payload(context(channel_store, close_payload(600)))
    with pytest.raises(InvalidSignatureError, match="close authorization"):
        await broadcast_credential_payload(
            context(channel_store, close_payload(900, close_signer=STRANGER))
        )
    with pytest.raises(BadRequestError, match="not the channel payee"):
        await broadcast_credential_payload(
            context(channel_store, close_payload(900), account=STRANGER)
        )


async def test_failed_close_before_send_clears_pending_marker(
    chain_state: list[chain.ChannelState], monkeypatch: pytest.MonkeyPatch
) -> None:
    channel_store = await seeded_store(spent=100, highest=100)
    close = FakeClose(monkeypatch, fail=RuntimeError("estimate failed"))
    close.send = False
    with pytest.raises(RuntimeError):
        await broadcast_credential_payload(context(channel_store, close_payload(100)))
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.close_requested_at == 0


async def test_failed_close_after_send_keeps_pending_marker(
    chain_state: list[chain.ChannelState], monkeypatch: pytest.MonkeyPatch
) -> None:
    channel_store = await seeded_store(spent=100, highest=100)
    FakeClose(monkeypatch, fail=TimeoutError("receipt"))
    failures: list[Any] = []
    with pytest.raises(TimeoutError):
        await broadcast_credential_payload(
            context(
                channel_store, close_payload(100), on_session_settlement_failure=failures.append
            )
        )
    channel = await channel_store.get_channel(CHANNEL_ID)
    # The close may still land: charges stop until it expires and is reconciled.
    assert channel is not None and channel.close_requested_at != 0
    assert [f.trigger for f in failures] == ["close"]
    with pytest.raises(ChannelClosedError):
        await charge_session_channel(channel_store, CHANNEL_ID, 1)


# --------------------------------------------------------------------------------------------
# Charge and credit
# --------------------------------------------------------------------------------------------


async def test_charge_is_idempotent_per_key() -> None:
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=500)
    first = await charge(raw, CHANNEL_ID, 200, idempotency_key="job-1")
    again = await charge(raw, CHANNEL_ID, 200, idempotency_key="job-1")
    assert first.spent == again.spent == 200
    with pytest.raises(IdempotencyKeyConflictError):
        await charge(raw, CHANNEL_ID, 300, idempotency_key="job-1")
    with pytest.raises(InsufficientBalanceError, match="available 300"):
        await charge(channel_store, CHANNEL_ID, 400)
    with pytest.raises(ChannelClosedError):
        await charge(raw, "0x" + "ff" * 32, 1)


async def test_credit_is_recorded_once_and_declines_below_settled() -> None:
    raw = MemoryStore()
    await _seed_into(raw, highest=500, spent=400, settled=100)
    result = await credit(raw, CHANNEL_ID, 100, idempotency_key="refund-1")
    assert (
        result.status == "credited" and result.channel is not None and result.channel.spent == 300
    )
    replay = await credit(raw, CHANNEL_ID, 100, idempotency_key="refund-1")
    assert replay.status == "credited" and replay.replayed and replay.channel is not None
    assert replay.channel.spent == 300
    declined = await credit(raw, CHANNEL_ID, 250, idempotency_key="refund-2")
    assert declined.status == "declined" and declined.reason == "belowSettled"


async def _seed_into(
    raw: MemoryStore, *, highest: int, spent: int = 0, settled: int = 0
) -> StoreChannelStore:
    channel_store = from_store(raw)

    def update(current: ChannelState | None) -> ChannelState:
        state = open_channel_state(
            authorized_signer=PAYER.address,
            chain_id=CHAIN_ID,
            channel_id=CHANNEL_ID,
            current=current,
            descriptor=DESCRIPTOR,
            escrow=ESCROW_ADDRESS,
            expiring_nonce_hash=DESCRIPTOR.expiring_nonce_hash,
            cumulative_amount=highest,
            signature=sign(highest),
            state=on_chain(DEPOSIT, settled),
        )
        return replace(state, spent=spent, units=spent // 100)

    await channel_store.update_channel(CHANNEL_ID, update)
    return channel_store


# --------------------------------------------------------------------------------------------
# Settlement (Settlement.test.ts)
# --------------------------------------------------------------------------------------------


class FakeSettle:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, delay: float = 0) -> None:
        self.calls: list[int] = []
        self.delay = delay
        self.revert = False
        monkeypatch.setattr(chain, "settle_on_chain", self.settle_on_chain)
        monkeypatch.setattr(chain, "wait_for_successful_receipt", self.wait)
        monkeypatch.setattr(chain, "get_channel_event", self.event)
        monkeypatch.setattr(chain, "get_channel_state", self.state)

    async def settle_on_chain(
        self,
        rpc_url: str,
        account: Any,
        descriptor: Any,
        amount: int,
        signature: str,
        **kwargs: Any,
    ) -> str:
        if self.delay:
            await asyncio.sleep(self.delay)
        self.calls.append(amount)
        return "0x" + "dd" * 32

    async def wait(self, rpc_url: str, tx_hash: str, **kwargs: Any) -> dict[str, Any]:
        if self.revert:
            raise VerificationFailedError("precompile transaction reverted")
        return {"transactionHash": tx_hash, "blockNumber": "0x20", "logs": []}

    def event(self, receipt: Any, name: str, channel_id: str, **kwargs: Any) -> dict[str, Any]:
        amount = self.calls[-1]
        return {"channelId": channel_id, "deltaPaid": amount, "newSettled": amount}

    async def state(self, rpc_url: str, channel_id: str, **kwargs: Any) -> chain.ChannelState:
        return on_chain(settled=self.calls[-1] if self.calls else 0)


async def test_settle_captures_largest_voucher_within_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeSettle(monkeypatch)
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=300, spent=300)
    # A later voucher above spend (prepaid) is not settled whole.
    await channel_store.update_channel(
        CHANNEL_ID,
        lambda c: open_channel_state(
            authorized_signer=PAYER.address,
            chain_id=CHAIN_ID,
            channel_id=CHANNEL_ID,
            current=c,
            descriptor=DESCRIPTOR,
            escrow=ESCROW_ADDRESS,
            expiring_nonce_hash=DESCRIPTOR.expiring_nonce_hash,
            cumulative_amount=600,
            signature=sign(600),
            state=on_chain(),
        ),
    )
    events: list[SessionSettlementContext] = []
    tx_hash = await settle(
        raw,
        CHANNEL_ID,
        account=PAYEE,
        rpc_url="http://rpc.invalid",
        on_session_settlement=events.append,
    )
    assert tx_hash == "0x" + "dd" * 32
    assert fake.calls == [300]
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.settled_on_chain == 300
    assert channel.last_settlement_spent == 300 and channel.pending_settlement is None
    assert [(e.trigger, e.amount, e.delta) for e in events] == [("settle", 300, 300)]
    with pytest.raises(VerificationFailedError, match="nothing to settle"):
        await settle(raw, CHANNEL_ID, account=PAYEE, rpc_url="http://rpc.invalid")


async def test_settle_requires_payee_or_operator_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSettle(monkeypatch)
    raw = MemoryStore()
    await _seed_into(raw, highest=300, spent=300)
    with pytest.raises(BadRequestError):
        await settle(raw, CHANNEL_ID, account=STRANGER, rpc_url="http://rpc.invalid")


async def test_reverted_settle_releases_credit_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeSettle(monkeypatch)
    fake.revert = True
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=300, spent=300)
    with pytest.raises(VerificationFailedError):
        await settle(raw, CHANNEL_ID, account=PAYEE, rpc_url="http://rpc.invalid")
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.pending_settlement is None


async def test_scheduled_settlement_runs_once_under_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeSettle(monkeypatch, delay=0.05)
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=300, spent=300)
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None
    schedule = ResolvedSettlementSchedule(units=2)

    async def run() -> str | None:
        return await maybe_settle_scheduled(
            channel=channel,
            schedule=schedule,
            store=channel_store,
            account=PAYEE,
            rpc_url="http://rpc.invalid",
        )

    results = await asyncio.gather(run(), run(), run())
    assert sorted(r is not None for r in results) == [False, False, True]
    assert fake.calls == [300]
    settled = await channel_store.get_channel(CHANNEL_ID)
    assert settled is not None and settled.scheduled_settlement_lease is None
    assert settled.last_settlement_at is not None
    # Not due again until two more units are paid.
    assert (
        await maybe_settle_scheduled(
            channel=settled,
            schedule=schedule,
            store=channel_store,
            account=PAYEE,
            rpc_url="http://rpc.invalid",
        )
        is None
    )


async def test_scheduled_settlement_skips_while_another_worker_holds_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeSettle(monkeypatch)
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=300, spent=300)
    from mpp.methods.tempo.session.server.schedule import claim_scheduled_settlement

    schedule = ResolvedSettlementSchedule(units=1)
    owner = await claim_scheduled_settlement(
        channel_id=CHANNEL_ID, schedule=schedule, store=channel_store
    )
    assert owner is not None
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None
    assert (
        await maybe_settle_scheduled(
            channel=channel,
            schedule=schedule,
            store=channel_store,
            account=PAYEE,
            rpc_url="http://rpc.invalid",
        )
        is None
    )
    assert fake.calls == []


async def test_scheduled_settlement_failures_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=300, spent=300)
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None

    async def unreachable(*args: Any, **kwargs: Any) -> str:
        raise httpx.ConnectError("down")

    monkeypatch.setattr(chain, "settle_on_chain", unreachable)
    failures: list[Any] = []
    with pytest.raises(Exception) as raised:
        await maybe_settle_scheduled(
            channel=channel,
            schedule=ResolvedSettlementSchedule(units=1),
            store=channel_store,
            account=PAYEE,
            rpc_url="http://rpc.invalid",
            on_session_settlement_failure=failures.append,
        )
    assert [f.trigger for f in failures] == ["scheduled"]
    # Transport failures keep the charged request served; the next settlement retries.
    assert ignore_retryable_settlement_failure(raised.value) is None
    with pytest.raises(BadRequestError):
        ignore_retryable_settlement_failure(BadRequestError("nope"))
    assert ignore_retryable_settlement_failure(SettlementLeaseError(cause=RuntimeError())) is None
    released = await channel_store.get_channel(CHANNEL_ID)
    assert released is not None and released.scheduled_settlement_lease is None


# --------------------------------------------------------------------------------------------
# Close supervision (CloseSupervisor.test.ts)
# --------------------------------------------------------------------------------------------


class FakeSupervisorChain:
    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, states: dict[str, chain.ChannelState]
    ) -> None:
        self.states = states
        self.logs: list[dict[str, Any]] = []
        self.closes: list[int] = []
        monkeypatch.setattr(chain, "_rpc", self.rpc)
        monkeypatch.setattr(chain, "get_channel_states_batch", self.batch)
        FakeClose(monkeypatch)  # receipts and events
        monkeypatch.setattr(chain, "close_on_chain", self.close_on_chain)
        monkeypatch.setattr(chain, "get_channel_event", self.event)

    def event(self, receipt: Any, name: str, channel_id: str, **kwargs: Any) -> dict[str, Any]:
        capture = self.closes[-1]
        return {
            "channelId": channel_id,
            "settledToPayee": capture,
            "refundedToPayer": DEPOSIT - capture,
        }

    async def rpc(self, rpc_url: str, method: str, params: list[Any], client: Any) -> Any:
        if method == "eth_getBlockByNumber":
            return {"number": hex(1_000), "timestamp": hex(1_700_000_000)}
        if method == "eth_getLogs":
            return self.logs
        raise AssertionError(method)

    async def batch(self, rpc_url: str, ids: Any, **kwargs: Any) -> list[chain.ChannelState]:
        assert kwargs["block"] == 1_000
        return [self.states[i] for i in ids]

    async def close_on_chain(
        self,
        rpc_url: str,
        account: Any,
        descriptor: Any,
        cumulative: int,
        capture: int,
        signature: str,
        **kwargs: Any,
    ) -> str:
        self.closes.append(capture)
        return "0x" + "cc" * 32


def channel_closed_log(settled_to_payee: int) -> dict[str, Any]:
    from eth_abi.abi import encode

    return {
        "address": ESCROW_ADDRESS,
        "topics": [
            abi.EVENT_TOPICS["ChannelClosed"],
            CHANNEL_ID,
            "0x" + PAYER.address[2:].lower().rjust(64, "0"),
            "0x" + PAYEE.address[2:].lower().rjust(64, "0"),
        ],
        "data": "0x"
        + encode(["uint96", "uint96"], [settled_to_payee, DEPOSIT - settled_to_payee]).hex(),
    }


async def test_supervisor_answers_close_request_at_spend(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=900, spent=600)
    fake = FakeSupervisorChain(monkeypatch, {CHANNEL_ID: on_chain(close=1_699_999_000)})
    supervision = await supervise_closes(
        channel_ids=[CHANNEL_ID, "0x" + "ee" * 32],
        store=raw,
        account=PAYEE,
        rpc_url="http://rpc.invalid",
    )
    assert fake.closes == [600]
    assert [(c.outcome) for c in supervision.channels] == ["missing", "closed"]
    assert supervision.closed == 1 and supervision.complete and supervision.block == 1_000
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.finalized


async def test_supervisor_finalizes_withdrawn_channel_from_close_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=900, spent=600)
    await channel_store.update_channel(
        CHANNEL_ID, lambda c: replace(c, close_supervised_from_block=900) if c else c
    )
    fake = FakeSupervisorChain(monkeypatch, {CHANNEL_ID: on_chain(deposit=0)})
    fake.logs = [channel_closed_log(200)]
    supervision = await supervise_closes(
        channel_ids=[CHANNEL_ID], store=raw, account=PAYEE, rpc_url="http://rpc.invalid"
    )
    # The payer withdrew before the server captured its spend.
    assert [c.outcome for c in supervision.channels] == ["unrecovered"]
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.finalized and channel.settled_on_chain == 200
    again = await supervise_closes(
        channel_ids=[CHANNEL_ID], store=raw, account=PAYEE, rpc_url="http://rpc.invalid"
    )
    assert [c.outcome for c in again.channels] == ["finalized"]


async def test_supervisor_marks_open_channels_and_settles_on_schedule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=300, spent=300)
    FakeSupervisorChain(monkeypatch, {CHANNEL_ID: on_chain()})
    supervision = await supervise_closes(
        channel_ids=[CHANNEL_ID], store=raw, account=PAYEE, rpc_url="http://rpc.invalid"
    )
    assert [c.outcome for c in supervision.channels] == ["open"]
    channel = await channel_store.get_channel(CHANNEL_ID)
    assert channel is not None and channel.close_supervised_from_block == 1_000
    settle_fake = FakeSettle(monkeypatch)
    supervision = await supervise_closes(
        channel_ids=[CHANNEL_ID],
        store=raw,
        account=PAYEE,
        rpc_url="http://rpc.invalid",
        settlement_schedule=ResolvedSettlementSchedule(units=1),
    )
    assert [c.outcome for c in supervision.channels] == ["settled"]
    assert settle_fake.calls == [300]


async def test_supervisor_reports_cancelled_close_request(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = MemoryStore()
    channel_store = await _seed_into(raw, highest=300, spent=300)
    await channel_store.update_channel(
        CHANNEL_ID,
        lambda c: replace(c, close_requested_at=1_000, close_supervised_from_block=10) if c else c,
    )
    FakeSupervisorChain(monkeypatch, {CHANNEL_ID: on_chain()})
    supervision = await supervise_closes(
        channel_ids=[CHANNEL_ID], store=raw, account=PAYEE, rpc_url="http://rpc.invalid"
    )
    assert [c.outcome for c in supervision.channels] == ["cancelled"]
    assert supervision.cancelled == 1


# --------------------------------------------------------------------------------------------
# Request classification
# --------------------------------------------------------------------------------------------


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
def test_session_content_request_classifier(
    method: str, url: str, headers: dict[str, str], body: bytes | None, content: bool
) -> None:
    probe = request_state.capture_request_probe(Request(method, url, headers=headers, body=body))
    assert request_state.is_session_content_request(probe) is content
    response = request_state.respond_to_session_credential(payload_action="voucher", request=probe)
    assert (response is None) is content
    top_up = request_state.respond_to_session_credential(payload_action="topUp", request=probe)
    assert top_up is not None and top_up.status == 204


# --------------------------------------------------------------------------------------------
# The session method through the engine (Session.test.ts)
# --------------------------------------------------------------------------------------------


def make_server(store: MemoryStore, **options: Any) -> Mpp:
    return Mpp(
        methods=[
            tempo_server.session(
                account=PAYEE,
                currency=CURRENCY,
                chain_id=CHAIN_ID,
                rpc_url="http://rpc.invalid",
                store=store,
                **options,
            )
        ],
        realm=REALM,
        secret_key=SECRET,
    )


async def challenge_for(handler: Any, request: Request) -> Challenge:
    result = await handler(request)
    assert isinstance(result, PaymentRequired), result
    return Challenge.from_www_authenticate(result.challenge.headers["www-authenticate"])


def authorize(challenge: Challenge, payload: dict[str, Any]) -> dict[str, str]:
    credential = Credential(challenge=challenge.to_echo(), payload=payload, source=SOURCE)
    return {"Authorization": credential.to_authorization()}


def decode_header(value: str) -> dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


async def test_session_method_charges_content_and_sends_mppx_receipt(
    chain_state: list[chain.ChannelState],
) -> None:
    raw = MemoryStore()
    await _seed_into(raw, highest=100, spent=100)
    handler = make_server(raw).session(amount="0.0001", unit_type="request")
    url = "http://api.test/paid"
    challenge = await challenge_for(handler, Request("GET", url))
    assert challenge.request["amount"] == "100"
    assert challenge.request["methodDetails"] == {
        "chainId": CHAIN_ID,
        "escrowContract": ESCROW_ADDRESS,
        "sessionProtocol": "v2",
    }
    result = await handler(
        Request("GET", url, headers=authorize(challenge, voucher_payload(200).to_wire()))
    )
    assert isinstance(result, PaymentVerified) and result.response is None
    assert isinstance(result.receipt, SessionPaymentReceipt)
    header = result.with_receipt(Response(200)).headers["payment-receipt"]
    receipt = decode_header(header)
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
    assert receipt["challengeId"] == challenge.id and receipt["reference"] == CHANNEL_ID
    assert receipt["units"] == 2
    assert len(receipt["timestamp"]) == len("2026-01-01T00:00:00.000Z")


async def test_session_method_answers_management_requests_with_204(
    chain_state: list[chain.ChannelState],
) -> None:
    raw = MemoryStore()
    await _seed_into(raw, highest=100, spent=100)
    handler = make_server(raw).session(amount="0.0001", unit_type="request")
    url = "http://api.test/paid"
    challenge = await challenge_for(handler, Request("POST", url))
    result = await handler(
        Request("POST", url, headers=authorize(challenge, voucher_payload(300).to_wire()))
    )
    assert isinstance(result, PaymentVerified) and result.response is not None
    assert result.response.status == 204
    assert decode_header(result.response.headers["payment-receipt"])["acceptedCumulative"] == "300"
    channel = await from_store(raw).get_channel(CHANNEL_ID)
    # A management voucher is accepted but nothing is charged.
    assert channel is not None and channel.spent == 100 and channel.highest_voucher_amount == 300


async def test_session_method_rejects_replayed_voucher(
    chain_state: list[chain.ChannelState],
) -> None:
    raw = MemoryStore()
    await _seed_into(raw, highest=100, spent=100)
    handler = make_server(raw).session(amount="0.0001", unit_type="request")
    url = "http://api.test/paid"
    challenge = await challenge_for(handler, Request("GET", url))
    headers = authorize(challenge, voucher_payload(200).to_wire())
    assert isinstance(await handler(Request("GET", url, headers=headers)), PaymentVerified)
    replay = await handler(Request("GET", url, headers=headers))
    assert isinstance(replay, PaymentRequired) and replay.status == 402
    assert json.loads(replay.challenge.body or b"")["type"].endswith("/delta-too-small")
    channel = await from_store(raw).get_channel(CHANNEL_ID)
    assert channel is not None and channel.spent == 200


async def test_insufficient_voucher_is_refused(chain_state: list[chain.ChannelState]) -> None:
    raw = MemoryStore()
    await _seed_into(raw, highest=100, spent=100)
    handler = make_server(raw).session(amount="0.0002", unit_type="request")
    url = "http://api.test/paid"
    challenge = await challenge_for(handler, Request("GET", url))
    result = await handler(
        Request("GET", url, headers=authorize(challenge, voucher_payload(200).to_wire()))
    )
    assert isinstance(result, PaymentRequired)
    assert json.loads(result.challenge.body or b"")["type"].endswith("/insufficient-balance")


async def test_fee_payer_is_advertised(chain_state: list[chain.ChannelState]) -> None:
    sponsor = TempoAccount.from_key("0x" + "44" * 32)
    handler = make_server(MemoryStore(), fee_payer=sponsor, fee_token=CURRENCY).session(
        amount="0.0001", unit_type="request", suggested_deposit="1"
    )
    challenge = await challenge_for(handler, Request("GET", "http://api.test/paid"))
    assert challenge.request["methodDetails"]["feePayer"] is True
    assert challenge.request["methodDetails"]["feeToken"] == CURRENCY
    assert challenge.request["suggestedDeposit"] == "1000000"
    no_sponsor = make_server(MemoryStore(), fee_payer=sponsor).session(
        amount="0.0001", unit_type="request", fee_payer=False
    )
    challenge = await challenge_for(no_sponsor, Request("GET", "http://api.test/paid"))
    assert "feePayer" not in challenge.request["methodDetails"]


@pytest.mark.parametrize("reusable", [True, False])
async def test_reusable_challenge_pays_later_price(
    chain_state: list[chain.ChannelState], reusable: bool
) -> None:
    raw = MemoryStore()
    await _seed_into(raw, highest=100, spent=100)
    server = make_server(raw, reusable_challenges=reusable)
    url = "http://api.test/paid"
    challenge = await challenge_for(
        server.session(amount="0.0001", unit_type="request"), Request("GET", url)
    )
    # The route's price changed since the challenge was issued.
    pricier = server.session(amount="0.0003", unit_type="request")
    result = await pricier(
        Request("GET", url, headers=authorize(challenge, voucher_payload(400).to_wire()))
    )
    if not reusable:
        assert isinstance(result, PaymentRequired)
        return
    assert isinstance(result, PaymentVerified)
    channel = await from_store(raw).get_channel(CHANNEL_ID)
    # Charged the route's current price, not the challenge's quote.
    assert channel is not None and channel.spent == 400
    # Still bound to the route: another path is refused.
    other = await pricier(
        Request(
            "GET",
            "http://api.test/other",
            headers=authorize(challenge, voucher_payload(700).to_wire()),
        )
    )
    assert isinstance(other, PaymentRequired)


async def test_scheduled_settlement_through_the_method(
    chain_state: list[chain.ChannelState], monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = MemoryStore()
    await _seed_into(raw, highest=100, spent=100)
    fake = FakeSettle(monkeypatch)
    # FakeSettle replaces chain reads; keep the voucher's on-chain state open.
    settlements: list[SessionSettlementContext] = []
    handler = make_server(
        raw,
        settlement_schedule=SettlementSchedule(units=2),
        on_session_settlement=settlements.append,
    ).session(amount="0.0001", unit_type="request")
    url = "http://api.test/paid"
    challenge = await challenge_for(handler, Request("GET", url))
    result = await handler(
        Request("GET", url, headers=authorize(challenge, voucher_payload(200).to_wire()))
    )
    assert isinstance(result, PaymentVerified)
    receipt = decode_header(result.receipt.to_payment_receipt())
    assert receipt["txHash"] == "0x" + "dd" * 32
    assert fake.calls == [200]
    assert [(s.trigger, s.amount) for s in settlements] == [("scheduled", 200)]


def test_session_factory_is_exported() -> None:
    from mpp.methods.tempo.session import server as session_server

    method = tempo_server.session(
        account=PAYEE, chain_id=CHAIN_ID, rpc_url="http://rpc.invalid", store=MemoryStore()
    )
    assert method.key == "tempo/session" and method.respond is not None
    assert method.stable_binding is None
    assert callable(session_server.charge) and callable(session_server.supervise_closes)
