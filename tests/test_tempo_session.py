"""Client lifecycle, durability, and HTTP tests for TIP-1034 sessions."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.client import PaymentTransport
from mpp.methods.tempo import TempoAccount, tempo
from mpp.methods.tempo.session import (
    AsyncSessionPaymentTransport,
    ChannelDescriptor,
    ChannelState,
    MemorySessionStore,
    NeedVoucherEvent,
    PendingStatus,
    SessionEvent,
    SessionPaymentTransport,
    SessionPolicy,
    SessionRecord,
    SessionStatus,
    SQLiteSessionStore,
    SseFrame,
    TempoAccountCredentialProvider,
    TempoSessionManager,
    TempoSessionProtocol,
    TempoSessionRpc,
    VoucherPlan,
    channel_scope,
    compute_channel_id,
    resolve_opening_deposit,
    resolve_top_up,
    resolve_voucher_plan,
    transition,
    verify_voucher_signature,
    voucher_digest,
)
from mpp.methods.tempo.session.sse import parse_need_voucher, parse_receipt

PAYER = "0x1111111111111111111111111111111111111111"
PAYEE = "0x2222222222222222222222222222222222222222"
OPERATOR = "0x3333333333333333333333333333333333333333"
TOKEN = "0x4444444444444444444444444444444444444444"
ESCROW = "0x4D50500000000000000000000000000000000000"
CHAIN_ID = 42431
RESOURCE = "https://service.example/stream"


def descriptor() -> ChannelDescriptor:
    return ChannelDescriptor(
        payer=PAYER,
        payee=PAYEE,
        operator=OPERATOR,
        token=TOKEN,
        salt="0x" + "00" * 31 + "01",
        authorized_signer=PAYER,
        expiring_nonce_hash="0x" + "aa" * 32,
    )


def challenge(
    challenge_id: str = "challenge-1",
    *,
    amount: int = 10,
    suggested_deposit: int = 100,
    snapshot: dict[str, Any] | None = None,
    recipient: str = PAYEE,
    protocol: str = "v2",
    min_voucher_delta: int = 0,
    chain_id: int = CHAIN_ID,
    escrow: str = ESCROW,
) -> Challenge:
    details: dict[str, Any] = {
        "chainId": chain_id,
        "escrowContract": escrow,
        "operator": OPERATOR,
        "sessionProtocol": protocol,
        "minVoucherDelta": str(min_voucher_delta),
    }
    if snapshot is not None:
        details["sessionSnapshot"] = snapshot
    request = {
        "amount": str(amount),
        "currency": TOKEN,
        "recipient": recipient,
        "suggestedDeposit": str(suggested_deposit),
        "methodDetails": details,
    }
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(request, separators=(",", ":"), sort_keys=True).encode()
        )
        .decode()
        .rstrip("=")
    )
    return Challenge(
        id=challenge_id,
        method="tempo",
        intent="session",
        request=request,
        realm="service.example",
        request_b64=encoded,
    )


def json_header(value: dict[str, Any]) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )


def receipt_header(
    credential: Credential,
    *,
    accepted: int,
    spent: int = 0,
    tx_hash: str | None = None,
) -> str:
    channel_id = str(credential.payload["channelId"])
    value: dict[str, Any] = {
        "method": "tempo",
        "intent": "session",
        "status": "success",
        "timestamp": "2026-08-06T12:00:00Z",
        "reference": channel_id,
        "challengeId": credential.challenge.id,
        "channelId": channel_id,
        "acceptedCumulative": str(accepted),
        "spent": str(spent),
    }
    if tx_hash is not None:
        value["txHash"] = tx_hash
    return json_header(value)


@dataclass(slots=True)
class FakeProvider:
    payer_address: str = PAYER
    signer_address: str = PAYER

    async def sign_transaction(self, transaction: Any) -> str:
        return str(transaction)

    async def sign_digest(self, digest: bytes) -> bytes:
        return digest + b"\x00" * 33


@dataclass(slots=True)
class FakeRpc:
    states: dict[str, ChannelState] = field(default_factory=dict)

    async def gas_price(self) -> int:
        return 1

    async def channel_state(self, escrow: str, channel_id: str) -> ChannelState:
        assert escrow.lower() == ESCROW.lower()
        return self.states.get(channel_id, ChannelState(0, 0, 0))


@dataclass(slots=True)
class FakeProtocol:
    provider: FakeProvider
    rpc: FakeRpc
    open_count: int = 0
    top_up_count: int = 0
    voucher_count: int = 0

    async def open_payload(self, **parameters: Any) -> dict[str, Any]:
        self.open_count += 1
        desc = descriptor()
        channel_id = compute_channel_id(desc, escrow=ESCROW, chain_id=CHAIN_ID)
        amount = parameters["initial_cumulative"]
        return {
            "action": "open",
            "type": "transaction",
            "channelId": channel_id,
            "transaction": f"0xopen{self.open_count}",
            "signature": "0x" + "11" * 65,
            "descriptor": desc.to_wire(),
            "cumulativeAmount": str(amount),
            "authorizedSigner": PAYER,
        }

    async def top_up_payload(self, **parameters: Any) -> dict[str, Any]:
        self.top_up_count += 1
        desc = parameters["descriptor"]
        return {
            "action": "topUp",
            "type": "transaction",
            "channelId": compute_channel_id(desc, escrow=ESCROW, chain_id=CHAIN_ID),
            "transaction": f"0xtopup{self.top_up_count}",
            "descriptor": desc.to_wire(),
            "additionalDeposit": str(parameters["additional_deposit"]),
        }

    async def voucher_payload(self, **parameters: Any) -> dict[str, Any]:
        self.voucher_count += 1
        desc = parameters["descriptor"]
        return {
            "action": parameters["action"],
            "channelId": compute_channel_id(desc, escrow=ESCROW, chain_id=CHAIN_ID),
            "descriptor": desc.to_wire(),
            "cumulativeAmount": str(parameters["cumulative_amount"]),
            "signature": "0x" + "22" * 65,
        }


def policy() -> SessionPolicy:
    return SessionPolicy(
        max_deposit=1_000,
        max_top_up=500,
        max_cumulative_spend=1_000,
    )


def manager(
    *,
    store: Any | None = None,
    rpc: FakeRpc | None = None,
    protocol: FakeProtocol | None = None,
    session_policy: SessionPolicy | None = None,
) -> tuple[TempoSessionManager, FakeRpc, FakeProtocol]:
    rpc = rpc or FakeRpc()
    provider = FakeProvider()
    protocol = protocol or FakeProtocol(provider, rpc)
    return (
        TempoSessionManager(
            provider=provider,
            store=store or MemorySessionStore(),
            policy=session_policy or policy(),
            rpc=rpc,
            chain_id=CHAIN_ID,
            protocol=protocol,  # type: ignore[arg-type]
        ),
        rpc,
        protocol,
    )


def active_record(
    *,
    deposit: int = 100,
    cumulative: int = 10,
    payee: str = PAYEE,
) -> SessionRecord:
    base = descriptor()
    desc = ChannelDescriptor(
        payer=base.payer,
        payee=payee,
        operator=base.operator,
        token=base.token,
        salt=base.salt,
        authorized_signer=base.authorized_signer,
        expiring_nonce_hash=base.expiring_nonce_hash,
    )
    return SessionRecord(
        scope=channel_scope(payee=payee, token=TOKEN, escrow=ESCROW, chain_id=CHAIN_ID),
        channel_id=compute_channel_id(desc, escrow=ESCROW, chain_id=CHAIN_ID),
        descriptor=desc,
        escrow=ESCROW,
        chain_id=CHAIN_ID,
        deposit=deposit,
        authorized_cumulative=cumulative,
        accepted_cumulative=cumulative,
        settled=0,
        spent=0,
        status=SessionStatus.ACTIVE,
        resource_url=RESOURCE,
    )


def snapshot_for(record: SessionRecord, *, required: int) -> dict[str, Any]:
    return {
        "acceptedCumulative": str(record.accepted_cumulative),
        "chainId": record.chain_id,
        "channelId": record.channel_id,
        "deposit": str(record.deposit),
        "descriptor": record.descriptor.to_wire(),
        "escrow": record.escrow,
        "requiredCumulative": str(required),
        "settled": str(record.settled),
        "spent": str(record.spent),
    }


class TestStateAndPolicy:
    @pytest.mark.asyncio
    async def test_manager_restricts_session_network(self) -> None:
        current, _, _ = manager()

        assert current.can_handle_challenge(challenge())
        assert not current.can_handle_challenge(challenge(protocol="v1"))
        assert not current.can_handle_challenge(challenge(chain_id=4217))
        assert not current.can_handle_challenge(
            challenge(escrow="0x0000000000000000000000000000000000000001")
        )
        with pytest.raises(ValueError, match="restricted to chain"):
            await current.prepare(challenge(chain_id=4217), resource_url=RESOURCE)
        with pytest.raises(ValueError, match="outside local policy"):
            await current.prepare(
                challenge(escrow="0x0000000000000000000000000000000000000001"),
                resource_url=RESOURCE,
            )

    def test_sse_control_frames_reject_malformed_data(self) -> None:
        with pytest.raises(ValueError, match="must be an object"):
            NeedVoucherEvent.from_wire([])
        with pytest.raises(ValueError, match="invalid payment-need-voucher amounts"):
            NeedVoucherEvent.from_wire(
                {
                    "channelId": "0x" + "ab" * 32,
                    "requiredCumulative": "nope",
                    "acceptedCumulative": "0",
                    "deposit": "0",
                }
            )
        with pytest.raises(ValueError, match="outside uint96 bounds"):
            NeedVoucherEvent.from_wire(
                {
                    "channelId": "0x" + "ab" * 32,
                    "requiredCumulative": str(1 << 96),
                    "acceptedCumulative": "0",
                    "deposit": "0",
                }
            )
        with pytest.raises(ValueError, match="invalid payment-need-voucher JSON"):
            parse_need_voucher(SseFrame("payment-need-voucher", "{", ""))
        with pytest.raises(ValueError, match="invalid payment-receipt JSON"):
            parse_receipt(SseFrame("payment-receipt", "{", ""))

    def test_pure_lifecycle_transitions(self) -> None:
        status = transition(None, SessionEvent.OPEN_PREPARED)
        assert status == SessionStatus.OPENING
        status = transition(status, SessionEvent.OPEN_ACCEPTED)
        assert status == SessionStatus.ACTIVE
        status = transition(status, SessionEvent.VOUCHER_PREPARED)
        assert status == SessionStatus.VOUCHER_PENDING
        assert transition(status, SessionEvent.VOUCHER_ACCEPTED) == SessionStatus.ACTIVE
        with pytest.raises(ValueError, match="invalid Tempo session transition"):
            transition(SessionStatus.CLOSED, SessionEvent.OPEN_PREPARED)

    def test_opening_and_top_up_limits(self) -> None:
        configured = SessionPolicy(
            max_deposit=100,
            max_top_up=30,
            max_cumulative_spend=90,
        )
        assert (
            resolve_opening_deposit(
                request_amount=10,
                suggested_deposit=80,
                policy=configured,
            )
            == 80
        )
        assert (
            resolve_top_up(
                deposit=70,
                required_cumulative=90,
                suggested_deposit=None,
                policy=configured,
            )
            == 20
        )
        with pytest.raises(ValueError, match="max cumulative spend"):
            resolve_top_up(
                deposit=70,
                required_cumulative=91,
                suggested_deposit=None,
                policy=configured,
            )

        assert resolve_voucher_plan(
            authorized_cumulative=10,
            accepted_cumulative=10,
            spent=10,
            request_amount=1,
            required_cumulative=None,
            deposit=80,
            suggested_deposit=None,
            policy=configured,
            min_voucher_delta=5,
        ) == VoucherPlan(cumulative=15, top_up=0)

    def test_channel_and_voucher_vectors_match_mppx(self) -> None:
        vector = json.loads(
            (Path(__file__).parent / "vectors" / "tempo-session-v2.json").read_text()
        )
        vector_descriptor = ChannelDescriptor.from_wire(vector["descriptor"])
        assert (
            compute_channel_id(
                vector_descriptor,
                escrow=vector["escrow"],
                chain_id=vector["chainId"],
            )
            == vector["channelId"]
        )
        assert voucher_digest(
            channel_id=vector["channelId"],
            cumulative_amount=int(vector["voucher"]["cumulativeAmount"]),
            chain_id=vector["chainId"],
            escrow=vector["escrow"],
        ).hex() == vector["voucher"]["digest"].removeprefix("0x")
        assert verify_voucher_signature(
            channel_id=vector["channelId"],
            cumulative_amount=int(vector["voucher"]["cumulativeAmount"]),
            signature=vector["voucher"]["signature"],
            expected_signer=vector["voucher"]["signer"],
            chain_id=vector["chainId"],
            escrow=vector["escrow"],
        )

        raw = bytes.fromhex(vector["voucher"]["signature"].removeprefix("0x"))
        parity = raw[64] - 27 if raw[64] >= 27 else raw[64]
        compact_s = int.from_bytes(raw[32:64], "big") | (parity << 255)
        compact = "0x" + (raw[:32] + compact_s.to_bytes(32, "big")).hex()
        assert verify_voucher_signature(
            channel_id=vector["channelId"],
            cumulative_amount=int(vector["voucher"]["cumulativeAmount"]),
            signature=compact,
            expected_signer=vector["voucher"]["signer"],
            chain_id=vector["chainId"],
            escrow=vector["escrow"],
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("fee_payer", [False, True])
    async def test_real_pytempo_open_payload_has_verifiable_voucher(self, fee_payer: bool) -> None:
        account = TempoAccount.from_key(
            "0xac0974bec39a17e36ba6a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        )
        provider = TempoAccountCredentialProvider(account)
        rpc = FakeRpc()
        protocol = TempoSessionProtocol(
            provider=provider,
            rpc=rpc,
            clock=lambda: 1_800_000_000,
            random_bytes=lambda length: b"\x12" * length,
        )
        payload = await protocol.open_payload(
            chain_id=CHAIN_ID,
            escrow=ESCROW,
            payee=PAYEE,
            operator=OPERATOR,
            token=TOKEN,
            deposit=100,
            initial_cumulative=10,
            fee_payer=fee_payer,
        )

        opened_descriptor = ChannelDescriptor.from_wire(payload["descriptor"])
        assert payload["transaction"].startswith("0x76")
        assert payload["channelId"] == compute_channel_id(
            opened_descriptor,
            escrow=ESCROW,
            chain_id=CHAIN_ID,
        )
        assert verify_voucher_signature(
            channel_id=payload["channelId"],
            cumulative_amount=10,
            signature=payload["signature"],
            expected_signer=account.address,
            chain_id=CHAIN_ID,
            escrow=ESCROW,
        )

    @pytest.mark.asyncio
    async def test_session_rpc_reads_gas_and_packed_channel_state(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, list[Any]]] = []

        async def rpc_call(_url: str, method: str, params: list[Any]) -> str:
            calls.append((method, params))
            if method == "eth_gasPrice":
                return "0x2a"
            return "0x" + b"".join(value.to_bytes(32, "big") for value in (3, 100, 7)).hex()

        monkeypatch.setattr("mpp.methods.tempo.session.protocol._rpc_call", rpc_call)
        rpc = TempoSessionRpc("https://rpc.example")

        assert await rpc.gas_price() == 42
        assert await rpc.channel_state(ESCROW, "0x" + "ab" * 32) == ChannelState(3, 100, 7)
        assert [method for method, _ in calls] == ["eth_gasPrice", "eth_call"]
        assert calls[1][1][0]["to"] == ESCROW


class TestPersistenceAndRecovery:
    @pytest.mark.asyncio
    async def test_open_honors_minimum_voucher_delta(self) -> None:
        current, _, _ = manager()

        credential = await current.prepare(
            challenge(amount=2, suggested_deposit=3, min_voucher_delta=5),
            resource_url=RESOURCE,
        )

        assert credential.payload["cumulativeAmount"] == "5"
        record = (await current.list_sessions())[0]
        assert record.authorized_cumulative == 5
        assert record.pending is not None
        assert record.pending.expected_deposit == 5
        await current.handle_unknown(credential)

    @pytest.mark.asyncio
    async def test_signed_server_snapshot_rehydrates_reusable_channel(self) -> None:
        account = TempoAccount.from_key(
            "0xac0974bec39a17e36ba6a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        )
        provider = TempoAccountCredentialProvider(account)
        desc = ChannelDescriptor(
            payer=account.address,
            payee=PAYEE,
            operator=OPERATOR,
            token=TOKEN,
            salt="0x" + "12" * 32,
            authorized_signer=account.address,
            expiring_nonce_hash="0x" + "34" * 32,
        )
        channel_id = compute_channel_id(desc, escrow=ESCROW, chain_id=CHAIN_ID)
        cumulative = 20
        signature = (
            "0x"
            + (
                await provider.sign_digest(
                    voucher_digest(
                        channel_id=channel_id,
                        cumulative_amount=cumulative,
                        chain_id=CHAIN_ID,
                        escrow=ESCROW,
                    )
                )
            ).hex()
        )
        snapshot = {
            "acceptedCumulative": str(cumulative),
            "chainId": CHAIN_ID,
            "channelId": channel_id,
            "deposit": "100",
            "descriptor": desc.to_wire(),
            "escrow": ESCROW,
            "highestVoucher": {
                "channelId": channel_id,
                "cumulativeAmount": str(cumulative),
                "signature": signature,
            },
            "requiredCumulative": "30",
            "settled": "3",
            "spent": "10",
            "units": 2,
        }
        rpc = FakeRpc({channel_id: ChannelState(3, 100, 0)})
        protocol = FakeProtocol(FakeProvider(), rpc)
        current = TempoSessionManager(
            provider=provider,
            store=MemorySessionStore(),
            policy=policy(),
            rpc=rpc,
            chain_id=CHAIN_ID,
            protocol=protocol,  # type: ignore[arg-type]
        )

        credential = await current.prepare(
            challenge(snapshot=snapshot),
            resource_url=RESOURCE,
        )

        assert credential.payload["action"] == "voucher"
        assert credential.payload["channelId"] == channel_id
        assert credential.payload["cumulativeAmount"] == "30"
        restored = (await current.list_sessions())[0]
        assert restored.deposit == 100
        assert restored.accepted_cumulative == 20
        assert restored.spent == 10
        assert restored.units == 2
        await current.handle_unknown(credential)

    @pytest.mark.asyncio
    async def test_sqlite_restart_reuses_exact_uncertain_open(self, tmp_path: Path) -> None:
        path = tmp_path / "sessions.sqlite3"
        first_store = SQLiteSessionStore(path)
        first, rpc, first_protocol = manager(store=first_store)
        first_credential = await first.prepare(challenge(), resource_url=RESOURCE)
        await first.handle_unknown(first_credential)
        first_store.close()

        second_store = SQLiteSessionStore(path)
        second_protocol = FakeProtocol(FakeProvider(), rpc)
        second, _, _ = manager(
            store=second_store,
            rpc=rpc,
            protocol=second_protocol,
        )
        retried = await second.prepare(challenge("challenge-2"), resource_url=RESOURCE)

        assert retried.payload == first_credential.payload
        assert retried.challenge.id == "challenge-2"
        assert first_protocol.open_count == 1
        assert second_protocol.open_count == 0
        persisted = (await second.list_sessions())[0]
        assert persisted.pending is not None
        assert persisted.pending.status == PendingStatus.UNCERTAIN
        await second.handle_unknown(retried)
        second_store.close()

    @pytest.mark.asyncio
    async def test_on_chain_open_without_server_ack_reuses_exact_open(self, tmp_path: Path) -> None:
        path = tmp_path / "sessions.sqlite3"
        first_store = SQLiteSessionStore(path)
        first, rpc, _ = manager(store=first_store)
        opened = await first.prepare(challenge(), resource_url=RESOURCE)
        await first.handle_unknown(opened)
        channel_id = str(opened.payload["channelId"])
        rpc.states[channel_id] = ChannelState(settled=0, deposit=100, close_requested_at=0)
        first_store.close()

        second_store = SQLiteSessionStore(path)
        second_protocol = FakeProtocol(FakeProvider(), rpc)
        second, _, _ = manager(
            store=second_store,
            rpc=rpc,
            protocol=second_protocol,
        )
        next_credential = await second.prepare(challenge("challenge-2"), resource_url=RESOURCE)

        assert next_credential.payload == opened.payload
        assert second_protocol.open_count == 0
        assert second_protocol.voucher_count == 0
        await second.handle_unknown(next_credential)
        second_store.close()

    @pytest.mark.asyncio
    async def test_server_snapshot_confirms_open_before_higher_voucher(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "sessions.sqlite3"
        first_store = SQLiteSessionStore(path)
        first, rpc, _ = manager(store=first_store)
        opened = await first.prepare(challenge(), resource_url=RESOURCE)
        await first.handle_unknown(opened)
        record = (await first.list_sessions())[0]
        rpc.states[record.channel_id] = ChannelState(0, 100, 0)
        first_store.close()

        acknowledged = snapshot_for(record, required=20)
        acknowledged.update(
            acceptedCumulative="10",
            deposit="100",
            spent="10",
        )
        second_store = SQLiteSessionStore(path)
        second_protocol = FakeProtocol(FakeProvider(), rpc)
        second, _, _ = manager(
            store=second_store,
            rpc=rpc,
            protocol=second_protocol,
        )
        next_credential = await second.prepare(
            challenge("challenge-2", snapshot=acknowledged),
            resource_url=RESOURCE,
        )

        assert next_credential.payload["action"] == "voucher"
        assert next_credential.payload["cumulativeAmount"] == "20"
        assert second_protocol.open_count == 0
        assert second_protocol.voucher_count == 1
        await second.handle_unknown(next_credential)
        second_store.close()

    @pytest.mark.asyncio
    async def test_uncertain_top_up_is_retried_exactly(self, tmp_path: Path) -> None:
        path = tmp_path / "sessions.sqlite3"
        record = active_record(deposit=20, cumulative=10)
        first_store = SQLiteSessionStore(path)
        await first_store.save(record)
        first, rpc, first_protocol = manager(store=first_store)
        rpc.states[record.channel_id] = ChannelState(0, 20, 0)
        challenged = challenge(snapshot=snapshot_for(record, required=40))
        top_up = await first.prepare(challenged, resource_url=RESOURCE)
        await first.handle_unknown(top_up)
        first_store.close()

        second_store = SQLiteSessionStore(path)
        second_protocol = FakeProtocol(FakeProvider(), rpc)
        second, _, _ = manager(
            store=second_store,
            rpc=rpc,
            protocol=second_protocol,
        )
        retried = await second.prepare(
            challenge("challenge-2", snapshot=snapshot_for(record, required=40)),
            resource_url=RESOURCE,
        )
        assert retried.payload == top_up.payload
        assert first_protocol.top_up_count == 1
        assert second_protocol.top_up_count == 0
        await second.handle_unknown(retried)
        second_store.close()

    @pytest.mark.asyncio
    async def test_cumulative_spend_policy_blocks_higher_voucher(self) -> None:
        record = active_record(deposit=100, cumulative=45)
        store = MemorySessionStore([record])
        configured = SessionPolicy(
            max_deposit=100,
            max_top_up=20,
            max_cumulative_spend=50,
        )
        current, _, _ = manager(store=store, session_policy=configured)
        with pytest.raises(ValueError, match="max cumulative spend"):
            await current.prepare(
                challenge(amount=10, suggested_deposit=100),
                resource_url=RESOURCE,
            )

    @pytest.mark.asyncio
    async def test_reconcile_updates_chain_state_and_session_hint(self) -> None:
        record = active_record(deposit=100, cumulative=20)
        store = MemorySessionStore([record])
        current, rpc, _ = manager(store=store)
        rpc.states[record.channel_id] = ChannelState(5, 120, 0)

        reconciled = await current.reconcile(record.channel_id)

        assert reconciled.deposit == 120
        assert reconciled.settled == 5
        assert await current.session_hint(RESOURCE) == record.channel_id
        assert await current.session_hint("https://other.example") is None

        rpc.states[record.channel_id] = ChannelState(0, 0, 0)
        closed = await current.reconcile(record.channel_id)
        assert closed.status == SessionStatus.CLOSED
        assert await current.session_hint(RESOURCE) is None

    @pytest.mark.asyncio
    async def test_close_is_persisted_and_finalized(self) -> None:
        record = active_record(deposit=100, cumulative=30)
        current, _, _ = manager(store=MemorySessionStore([record]))
        credential = await current.prepare_close(challenge(), record.channel_id)

        assert credential.payload["action"] == "close"
        assert credential.payload["cumulativeAmount"] == "30"
        await current.handle_response(
            credential,
            status_code=200,
            headers={
                "payment-receipt": receipt_header(
                    credential,
                    accepted=30,
                    spent=30,
                    tx_hash="0x" + "ab" * 32,
                )
            },
        )
        closed = (await current.list_sessions())[0]
        assert closed.status == SessionStatus.CLOSED
        assert closed.pending is None

    @pytest.mark.asyncio
    async def test_unrelated_channels_prepare_concurrently(self) -> None:
        other_payee = "0x6666666666666666666666666666666666666666"
        records = [active_record(), active_record(payee=other_payee)]
        rpc = FakeRpc()
        provider = FakeProvider()

        class ConcurrentProtocol(FakeProtocol):
            def __init__(self) -> None:
                super().__init__(provider, rpc)
                self.entered = 0
                self.both_entered = asyncio.Event()

            async def voucher_payload(self, **parameters: Any) -> dict[str, Any]:
                self.entered += 1
                if self.entered == 2:
                    self.both_entered.set()
                await asyncio.wait_for(self.both_entered.wait(), timeout=1)
                return await super().voucher_payload(**parameters)

        protocol = ConcurrentProtocol()
        current, _, _ = manager(
            store=MemorySessionStore(records),
            rpc=rpc,
            protocol=protocol,
        )
        first, second = await asyncio.gather(
            current.prepare(challenge("one"), resource_url=RESOURCE),
            current.prepare(
                challenge("two", recipient=other_payee),
                resource_url="https://other.example/stream",
            ),
        )
        assert protocol.entered == 2
        await asyncio.gather(
            current.handle_unknown(first),
            current.handle_unknown(second),
        )

    @pytest.mark.asyncio
    async def test_same_channel_waits_and_reuses_uncertain_operation(self) -> None:
        current, _, protocol = manager()
        first = await current.prepare(challenge("first"), resource_url=RESOURCE)
        second_task = asyncio.create_task(
            current.prepare(challenge("second"), resource_url=RESOURCE)
        )

        await asyncio.sleep(0.02)
        assert not second_task.done()
        await current.handle_unknown(first)
        second = await asyncio.wait_for(second_task, timeout=1)

        assert second.payload == first.payload
        assert second.challenge.id == "second"
        assert protocol.open_count == 1
        await current.handle_unknown(second)


class AsyncMockTransport(httpx.AsyncBaseTransport):
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


class SyncMockTransport(httpx.BaseTransport):
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


class AsyncChunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def __aiter__(self):  # type: ignore[no-untyped-def]
        for chunk in self.chunks:
            yield chunk


class SyncChunks(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    def __iter__(self):  # type: ignore[no-untyped-def]
        yield from self.chunks


class TestHttpxTransports:
    @pytest.mark.asyncio
    async def test_async_httpx_opens_and_commits_session(self) -> None:
        current, _, _ = manager()
        offered = challenge()
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=10, spent=10)},
                content=b"paid",
            )

        inner = AsyncMockTransport(handler)
        transport = AsyncSessionPaymentTransport(current, inner=inner)
        response = await transport.handle_async_request(httpx.Request("GET", RESOURCE))

        assert response.status_code == 200
        assert len(inner.requests) == 2
        record = (await current.list_sessions())[0]
        assert record.status == SessionStatus.ACTIVE
        assert record.pending is None
        assert record.accepted_cumulative == 10

    @pytest.mark.asyncio
    async def test_standard_payment_transport_routes_session_separately(self) -> None:
        current, _, _ = manager()
        offered = challenge()
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            assert credential.challenge.intent == "session"
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=10, spent=10)},
            )

        method = tempo(intents={}, chain_id=CHAIN_ID, session_manager=current)
        transport = PaymentTransport(methods=[method], inner=AsyncMockTransport(handler))
        response = await transport.handle_async_request(httpx.Request("GET", RESOURCE))

        assert response.status_code == 200
        assert (await current.list_sessions())[0].status == SessionStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_standard_transport_prefers_session_over_charge_alternative(self) -> None:
        current, _, _ = manager()
        offered = challenge()
        unsupported = challenge("unsupported", protocol="v1")
        charge = Challenge(
            id="charge-alternative",
            method="tempo",
            intent="charge",
            request=offered.request,
            realm=offered.realm,
            request_b64=offered.request_b64,
        )
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers=[
                        (
                            "www-authenticate",
                            unsupported.to_www_authenticate(unsupported.realm),
                        ),
                        ("www-authenticate", charge.to_www_authenticate(charge.realm)),
                        ("www-authenticate", offered.to_www_authenticate(offered.realm)),
                    ],
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            assert credential.challenge.intent == "session"
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=10, spent=10)},
            )

        method = tempo(intents={}, chain_id=CHAIN_ID, session_manager=current)
        transport = PaymentTransport(methods=[method], inner=AsyncMockTransport(handler))
        response = await transport.handle_async_request(httpx.Request("GET", RESOURCE))

        assert response.status_code == 200
        assert calls == 2

    @pytest.mark.asyncio
    async def test_standard_transport_ignores_unsupported_session_for_charge(self) -> None:
        current, _, _ = manager()
        unsupported = challenge("unsupported", protocol="v1")
        outside_policy = challenge("outside-policy", chain_id=4217)
        charge = Challenge(
            id="charge",
            method="tempo",
            intent="charge",
            request=unsupported.request,
            realm=unsupported.realm,
            request_b64=unsupported.request_b64,
        )

        class ChargeMethod:
            name = "tempo"
            session_manager = current

            async def create_credential(self, selected: Challenge) -> Credential:
                assert selected.id == charge.id
                assert selected.intent == "charge"
                return Credential(
                    challenge=selected.to_echo(),
                    payload={"type": "transaction", "signature": "0x76"},
                )

        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers=[
                        (
                            "www-authenticate",
                            unsupported.to_www_authenticate(unsupported.realm),
                        ),
                        (
                            "www-authenticate",
                            outside_policy.to_www_authenticate(outside_policy.realm),
                        ),
                        ("www-authenticate", charge.to_www_authenticate(charge.realm)),
                    ],
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            assert credential.challenge.intent == "charge"
            return httpx.Response(200)

        transport = PaymentTransport(
            methods=[ChargeMethod()],  # type: ignore[list-item]
            inner=AsyncMockTransport(handler),
        )
        response = await transport.handle_async_request(httpx.Request("GET", RESOURCE))

        assert response.status_code == 200
        assert calls == 2
        assert await current.list_sessions() == []

    def test_sync_httpx_opens_and_commits_session(self) -> None:
        current, _, _ = manager()
        offered = challenge()
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=10, spent=10)},
                content=b"paid",
            )

        inner = SyncMockTransport(handler)
        transport = SessionPaymentTransport(current, inner=inner)
        response = transport.handle_request(httpx.Request("GET", RESOURCE))

        assert response.status_code == 200
        assert len(inner.requests) == 2
        record = _sync_record(current)
        assert record.status == SessionStatus.ACTIVE
        assert record.pending is None

    @pytest.mark.asyncio
    async def test_sync_httpx_works_inside_a_running_event_loop(self) -> None:
        current, _, _ = manager()
        offered = challenge()
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=10, spent=10)},
            )

        transport = SessionPaymentTransport(current, inner=SyncMockTransport(handler))
        response = transport.handle_request(httpx.Request("GET", RESOURCE))

        assert response.status_code == 200
        assert (await current.list_sessions())[0].status == SessionStatus.ACTIVE

    def test_close_resolves_pending_voucher_then_closes(self) -> None:
        record = active_record(deposit=100, cumulative=10)
        store = MemorySessionStore([record])
        current, rpc, protocol = manager(store=store)
        rpc.states[record.channel_id] = ChannelState(0, 100, 0)
        pending = asyncio.run(current.prepare(challenge("pending"), resource_url=RESOURCE))
        asyncio.run(current.handle_unknown(pending))
        challenges = [challenge("close-1"), challenge("close-2")]
        actions: list[str] = []
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if request.method == "HEAD":
                offered = challenges.pop(0)
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            action = str(credential.payload["action"])
            actions.append(action)
            if action == "close":
                return httpx.Response(
                    200,
                    headers={
                        "payment-receipt": receipt_header(
                            credential,
                            accepted=20,
                            spent=20,
                            tx_hash="0x" + "ab" * 32,
                        )
                    },
                )
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=20, spent=20)},
            )

        transport = SessionPaymentTransport(current, inner=SyncMockTransport(handler))
        response = transport.close_session(record.channel_id, RESOURCE)

        assert response.status_code == 200
        assert actions == ["voucher", "close"]
        assert calls == 4
        assert protocol.voucher_count == 2
        assert _sync_record(current).status == SessionStatus.CLOSED

    @pytest.mark.asyncio
    async def test_async_close_session(self) -> None:
        record = active_record(deposit=100, cumulative=20)
        current, rpc, _ = manager(store=MemorySessionStore([record]))
        rpc.states[record.channel_id] = ChannelState(0, 100, 0)
        offered = challenge("close")
        methods: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            methods.append(request.method)
            if request.method == "HEAD":
                assert request.headers["payment-session"] == record.channel_id
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            assert credential.payload["action"] == "close"
            return httpx.Response(
                200,
                headers={
                    "payment-receipt": receipt_header(
                        credential,
                        accepted=20,
                        spent=20,
                        tx_hash="0x" + "ab" * 32,
                    )
                },
            )

        transport = AsyncSessionPaymentTransport(current, inner=AsyncMockTransport(handler))
        response = await transport.close_session(record.channel_id, RESOURCE)

        assert response.status_code == 200
        assert methods == ["HEAD", "POST"]
        assert (await current.list_sessions())[0].status == SessionStatus.CLOSED

    @pytest.mark.asyncio
    async def test_repeated_402_reconciles_open_before_higher_voucher(self) -> None:
        current, rpc, protocol = manager()
        offered = challenge()
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            if calls == 2:
                record = active_record(deposit=100, cumulative=10)
                rpc.states[record.channel_id] = ChannelState(0, 100, 0)
                next_challenge = challenge(
                    "challenge-2", snapshot=snapshot_for(record, required=20)
                )
                return httpx.Response(
                    402,
                    headers={
                        "www-authenticate": next_challenge.to_www_authenticate(
                            next_challenge.realm
                        ),
                        "payment-session-snapshot": json_header(snapshot_for(record, required=20)),
                    },
                )
            assert credential.payload["action"] == "voucher"
            assert credential.payload["cumulativeAmount"] == "20"
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=20, spent=20)},
            )

        inner = AsyncMockTransport(handler)
        transport = AsyncSessionPaymentTransport(current, inner=inner)
        response = await transport.handle_async_request(httpx.Request("GET", RESOURCE))

        assert response.status_code == 200
        assert protocol.open_count == 1
        assert protocol.voucher_count == 1
        assert [
            Credential.from_authorization(request.headers["authorization"]).payload["action"]
            for request in inner.requests[1:]
        ] == ["open", "voucher"]

    @pytest.mark.asyncio
    async def test_interrupted_retry_keeps_exact_operation(self) -> None:
        current, _, protocol = manager()
        offered = challenge()
        calls = 0
        submitted: dict[str, Any] | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls, submitted
            calls += 1
            if calls in {1, 3}:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            if calls == 2:
                submitted = credential.payload
                raise httpx.ReadTimeout("interrupted")
            assert credential.payload == submitted
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=10, spent=10)},
            )

        transport = AsyncSessionPaymentTransport(current, inner=AsyncMockTransport(handler))
        with pytest.raises(httpx.ReadTimeout):
            await transport.handle_async_request(httpx.Request("GET", RESOURCE))
        response = await transport.handle_async_request(httpx.Request("GET", RESOURCE))

        assert response.status_code == 200
        assert protocol.open_count == 1

    @pytest.mark.asyncio
    async def test_sse_drives_top_up_and_voucher_without_leaking_control_frames(
        self,
    ) -> None:
        current, _, _ = manager()
        offered = challenge(suggested_deposit=15)
        actions: list[str] = []
        calls = 0

        def stream_receipt(channel_id: str, *, accepted: int, spent: int) -> dict[str, Any]:
            return {
                "method": "tempo",
                "intent": "session",
                "status": "success",
                "timestamp": "2026-08-06T12:00:00Z",
                "reference": channel_id,
                "challengeId": offered.id,
                "channelId": channel_id,
                "acceptedCumulative": str(accepted),
                "spent": str(spent),
            }

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            action = str(credential.payload["action"])
            actions.append(action)
            if action == "open":
                channel_id = str(credential.payload["channelId"])
                event = {
                    "channelId": channel_id,
                    "requiredCumulative": "20",
                    "acceptedCumulative": "10",
                    "deposit": "15",
                }
                final = stream_receipt(channel_id, accepted=20, spent=20)
                chunks = [
                    b"event: message\ndata: first\n\n",
                    (
                        "event: payment-need-voucher\ndata: "
                        + json.dumps(event, separators=(",", ":"))
                        + "\n\n"
                    ).encode(),
                    b"event: message\ndata: second\n\n",
                    (
                        "event: payment-receipt\ndata: "
                        + json.dumps(final, separators=(",", ":"))
                        + "\n\n"
                    ).encode(),
                ]
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=AsyncChunks(chunks),
                )
            if action == "topUp":
                return httpx.Response(
                    200,
                    headers={"payment-receipt": receipt_header(credential, accepted=10, spent=5)},
                )
            assert action == "voucher"
            assert credential.payload["cumulativeAmount"] == "20"
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=20, spent=5)},
            )

        transport = AsyncSessionPaymentTransport(current, inner=AsyncMockTransport(handler))
        response = await transport.handle_async_request(httpx.Request("GET", RESOURCE))
        body = await response.aread()

        assert actions == ["open", "topUp", "voucher"]
        assert body == (b"event: message\ndata: first\n\nevent: message\ndata: second\n\n")
        record = (await current.list_sessions())[0]
        assert record.deposit == 20
        assert record.authorized_cumulative == 20
        assert record.accepted_cumulative == 20
        assert record.spent == 20

    def test_sync_sse_drives_top_up_and_voucher(self) -> None:
        current, _, _ = manager()
        offered = challenge(suggested_deposit=15)
        actions: list[str] = []
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            credential = Credential.from_authorization(request.headers["authorization"])
            action = str(credential.payload["action"])
            actions.append(action)
            if action == "open":
                channel_id = str(credential.payload["channelId"])
                event = {
                    "channelId": channel_id,
                    "requiredCumulative": "20",
                    "acceptedCumulative": "10",
                    "deposit": "15",
                }
                final = {
                    "method": "tempo",
                    "intent": "session",
                    "status": "success",
                    "timestamp": "2026-08-06T12:00:00Z",
                    "reference": channel_id,
                    "challengeId": offered.id,
                    "channelId": channel_id,
                    "acceptedCumulative": "20",
                    "spent": "20",
                }
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream", "content-length": "999"},
                    stream=SyncChunks(
                        [
                            b"event: message\r\ndata: first\r\n\r\n",
                            (
                                "event: payment-need-voucher\rdata: "
                                + json.dumps(event, separators=(",", ":"))
                                + "\r\r"
                            ).encode(),
                            b"event: message\ndata: second\n\n",
                            (
                                "event: payment-receipt\ndata: "
                                + json.dumps(final, separators=(",", ":"))
                            ).encode(),
                        ]
                    ),
                )
            if action == "topUp":
                assert request.method == "POST"
                assert request.content == b""
                return httpx.Response(
                    200,
                    headers={"payment-receipt": receipt_header(credential, accepted=10, spent=5)},
                )
            assert action == "voucher"
            return httpx.Response(
                200,
                headers={"payment-receipt": receipt_header(credential, accepted=20, spent=5)},
            )

        transport = SessionPaymentTransport(current, inner=SyncMockTransport(handler))
        response = transport.handle_request(
            httpx.Request("GET", RESOURCE, headers={"accept": "text/event-stream"})
        )
        body = response.read()
        response.close()

        assert actions == ["open", "topUp", "voucher"]
        assert response.headers.get("content-length") is None
        assert body == (b"event: message\r\ndata: first\r\n\r\nevent: message\ndata: second\n\n")
        record = _sync_record(current)
        assert record.deposit == 20
        assert record.authorized_cumulative == 20
        assert record.spent == 20

    @pytest.mark.asyncio
    async def test_sse_retries_after_management_only_open(self) -> None:
        current, rpc, _ = manager()
        offered = challenge()
        follow_up = challenge("challenge-2")
        actions: list[str] = []
        calls = 0
        opened: Credential | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls, opened
            calls += 1
            if calls == 1:
                return httpx.Response(
                    402,
                    headers={"www-authenticate": offered.to_www_authenticate(offered.realm)},
                )
            if calls == 3:
                assert request.headers["payment-session"]
                assert "authorization" not in request.headers
                assert opened is not None
                snapshot = {
                    "acceptedCumulative": "10",
                    "chainId": CHAIN_ID,
                    "channelId": opened.payload["channelId"],
                    "deposit": "100",
                    "descriptor": opened.payload["descriptor"],
                    "escrow": ESCROW,
                    "requiredCumulative": "20",
                    "settled": "0",
                    "spent": "10",
                }
                return httpx.Response(
                    402,
                    headers={
                        "www-authenticate": follow_up.to_www_authenticate(follow_up.realm),
                        "payment-session-snapshot": json_header(snapshot),
                    },
                )

            credential = Credential.from_authorization(request.headers["authorization"])
            action = str(credential.payload["action"])
            actions.append(action)
            if action == "open":
                opened = credential
                rpc.states[str(credential.payload["channelId"])] = ChannelState(0, 100, 0)
                return httpx.Response(
                    204,
                    headers={
                        "payment-receipt": receipt_header(
                            credential,
                            accepted=10,
                            spent=10,
                        )
                    },
                )
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/event-stream",
                    "payment-receipt": receipt_header(
                        credential,
                        accepted=20,
                        spent=20,
                    ),
                },
                stream=AsyncChunks([b"event: message\ndata: ready\n\n"]),
            )

        transport = AsyncSessionPaymentTransport(current, inner=AsyncMockTransport(handler))
        response = await transport.handle_async_request(
            httpx.Request("GET", RESOURCE, headers={"accept": "text/event-stream"})
        )

        assert await response.aread() == b"event: message\ndata: ready\n\n"
        assert actions == ["open", "voucher"]
        assert calls == 4


def _sync_record(manager: TempoSessionManager) -> SessionRecord:
    import asyncio

    return asyncio.run(manager.list_sessions())[0]
