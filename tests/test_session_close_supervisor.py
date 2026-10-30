"""Close supervision against a fake node (mppx server/CloseSupervisor.test.ts).

Channels are opened through the real verification and chain code (see
tests/session_helpers.py) and supervised with escrow reads, log searches and payee
closes answered by a fake JSON-RPC node.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from mpp.errors import VerificationFailedError
from mpp.methods.tempo.session import _abi as abi
from mpp.methods.tempo.session.server import supervise_closes
from mpp.methods.tempo.session.server._close_supervisor import CloseSupervision
from mpp.methods.tempo.session.server._schedule import ResolvedSettlementSchedule
from mpp.methods.tempo.session.server._settlement import (
    SessionSettlementContext,
    SessionSettlementFailureContext,
)
from tests.session_helpers import Lifecycle, closed_log, settled_log
from tests.test_session_chain import CHAIN_ID, DEPOSIT, PAYEE, PAYER, RPC

BLOCK = 1_000
NOW = 1_700_000_000
CLOSE_REQUESTED = NOW - 100


class Supervised(Lifecycle):
    """A channel opened at 900 with 600 spent, on a node that also serves blocks and logs."""

    def __init__(self) -> None:
        super().__init__()
        self.close_logs: list[Any] = []
        self.block: Any = {"number": hex(BLOCK), "timestamp": hex(NOW)}
        self.rpc.overrides["eth_getBlockByNumber"] = lambda params: self.block
        self.rpc.overrides["eth_getLogs"] = self._logs

    def _logs(self, params: list[Any]) -> list[Any]:
        query = params[0]
        start, end = int(query["fromBlock"], 16), int(query["toBlock"], 16)
        return [log for block, log in self.close_logs if start <= block <= end]

    @property
    def log_queries(self) -> list[tuple[int, int]]:
        return [
            (int(p[0]["fromBlock"], 16), int(p[0]["toBlock"], 16))
            for p in self.rpc.methods("eth_getLogs")
        ]

    async def supervise(self, **kwargs: Any) -> CloseSupervision:
        options: dict[str, Any] = {
            "channel_ids": [self.channel_id],
            "store": self.raw,
            "account": PAYEE,
            "rpc_url": RPC,
            "http_client": self.rpc.client,
        }
        options.update(kwargs)
        return await supervise_closes(**options)


@pytest.fixture
async def life() -> Supervised:
    life = Supervised()
    await life.build()
    await life.open(900)
    await life.update(spent=600, units=6)
    return life


def outcomes(supervision: CloseSupervision) -> list[str]:
    return [channel.outcome for channel in supervision.channels]


class TestCloseRequests:
    async def test_answers_a_close_request_with_a_payee_close_at_spend(
        self, life: Supervised
    ) -> None:
        life.rpc.states[life.channel_id] = (0, DEPOSIT, CLOSE_REQUESTED)
        life.rpc.logs = [closed_log(life.descriptor, life.channel_id, 600, DEPOSIT - 600)]
        settlements: list[SessionSettlementContext] = []
        supervision = await life.supervise(on_session_settlement=settlements.append)
        assert outcomes(supervision) == ["closed"]
        assert supervision.closed == 1 and supervision.complete
        assert supervision.channels[0].tx_hash == "0x" + f"{2:064x}"
        channel = await life.channel()
        assert channel.finalized and channel.settled_on_chain == 600
        assert [(s.trigger, s.amount, s.delta) for s in settlements] == [("close", 600, 600)]
        # The escrow was read at the pinned block.
        batch_read = [p for p in life.rpc.methods("eth_call") if p[1] == hex(BLOCK)]
        assert batch_read
        assert outcomes(await life.supervise()) == ["finalized"]

    async def test_nothing_to_capture_above_settled_is_closing(self, life: Supervised) -> None:
        life.rpc.states[life.channel_id] = (600, DEPOSIT, CLOSE_REQUESTED)
        assert outcomes(await life.supervise()) == ["closing"]
        channel = await life.channel()
        # The pending close stops charges: the record carries the on-chain request.
        assert channel.close_requested_at == CLOSE_REQUESTED and channel.settled_on_chain == 600

    @pytest.mark.parametrize(
        ("fields", "logged", "match"),
        [
            ({"highest_voucher": None}, None, "no voucher to close with"),
            ({}, (700, 0), "ChannelClosed amounts"),
            ({}, (600, DEPOSIT), "ChannelClosed amounts"),
        ],
    )
    async def test_failed_closes_are_reported_and_retried(
        self,
        life: Supervised,
        fields: dict[str, Any],
        logged: tuple[int, int] | None,
        match: str,
    ) -> None:
        if fields:
            await life.update(**fields)
        life.rpc.states[life.channel_id] = (0, DEPOSIT, CLOSE_REQUESTED)
        if logged is not None:
            life.rpc.logs = [closed_log(life.descriptor, life.channel_id, *logged)]
        failures: list[SessionSettlementFailureContext] = []
        supervision = await life.supervise(on_session_settlement_failure=failures.append)
        assert outcomes(supervision) == ["failed"] and not supervision.complete
        error = supervision.channels[0].error
        assert isinstance(error, VerificationFailedError) and match in str(error)
        assert [(f.trigger, f.channel_id) for f in failures] == [("close", life.channel_id)]
        assert not (await life.channel()).finalized

    async def test_close_needs_the_payee_or_operator(self, life: Supervised) -> None:
        life.rpc.states[life.channel_id] = (0, DEPOSIT, CLOSE_REQUESTED)
        supervision = await life.supervise(account=PAYER)
        assert outcomes(supervision) == ["failed"]
        assert not life.rpc.sent[1:]

    async def test_cancelled_request_reopens_the_channel(self, life: Supervised) -> None:
        await life.update(close_requested_at=CLOSE_REQUESTED, close_supervised_from_block=10)
        supervision = await life.supervise()
        assert outcomes(supervision) == ["cancelled"] and supervision.cancelled == 1
        assert (await life.channel()).close_requested_at == 0

    async def test_a_fresh_server_close_marker_is_kept(self, life: Supervised) -> None:
        # The server's own close may still land until its marker expires.
        await life.update(close_requested_at=NOW, close_supervised_from_block=10)
        assert outcomes(await life.supervise()) == ["open"]
        assert (await life.channel()).close_requested_at == NOW


class TestWithdrawnChannels:
    async def test_finalizes_from_the_close_event(self, life: Supervised) -> None:
        await life.update(close_supervised_from_block=900)
        life.rpc.states[life.channel_id] = (0, 0, 0)
        life.close_logs = [
            (950, {"removed": True, **closed_log(life.descriptor, life.channel_id, 1, 0)}),
            (951, "not a log"),
            (952, {"topics": None}),
            (953, closed_log(life.descriptor, "0x" + "99" * 32, 1, 0)),
            (954, settled_log(life.descriptor, life.channel_id, 1, 1)),
            (955, closed_log(life.descriptor, life.channel_id, 600, DEPOSIT - 600)),
        ]
        supervision = await life.supervise()
        assert outcomes(supervision) == ["closed"]
        channel = await life.channel()
        assert channel.finalized and channel.settled_on_chain == 600
        assert life.log_queries == [(900, BLOCK)]

    async def test_pages_through_the_search_range(self, life: Supervised) -> None:
        await life.update(close_supervised_from_block=700)
        life.rpc.states[life.channel_id] = (0, 0, 0)
        life.close_logs = [(990, closed_log(life.descriptor, life.channel_id, 100, 800))]
        supervision = await life.supervise(log_block_range=150, previous_block=750)
        assert outcomes(supervision) == ["unrecovered"] and supervision.unrecovered == 1
        # The search starts at the later of the record and the previous complete run.
        assert life.log_queries == [(750, 899), (900, BLOCK)]

    async def test_a_channel_never_marked_open_searches_back_a_margin(
        self, life: Supervised
    ) -> None:
        life.rpc.states[life.channel_id] = (0, 0, 0)
        # No close event: an open landing after the pinned block also reads as no deposit.
        assert outcomes(await life.supervise(close_search_margin_blocks=300)) == ["open"]
        assert life.log_queries == [(BLOCK - 300, BLOCK)]
        await life.supervise(previous_block=800, close_search_margin_blocks=300)
        assert life.log_queries[-1] == (500, BLOCK)

    async def test_missing_close_event_fails_a_supervised_channel(self, life: Supervised) -> None:
        await life.update(close_supervised_from_block=990)
        life.rpc.states[life.channel_id] = (0, 0, 0)
        supervision = await life.supervise(previous_block=980)
        assert outcomes(supervision) == ["failed"]
        assert "without a ChannelClosed event" in str(supervision.channels[0].error)


class TestOpenChannels:
    async def test_marks_open_channels_from_the_pinned_block(self, life: Supervised) -> None:
        assert outcomes(await life.supervise()) == ["open"]
        assert (await life.channel()).close_supervised_from_block == BLOCK

    async def test_settles_open_channels_on_schedule(self, life: Supervised) -> None:
        # A settlement captures a whole voucher, so the 900 voucher needs 900 spent.
        await life.update(spent=900, units=9)
        life.rpc.logs = [settled_log(life.descriptor, life.channel_id, 900, 900)]
        life.rpc.states[life.channel_id] = (0, DEPOSIT, 0)

        def settled_after_send(params: list[Any]) -> str:
            # Before the settle the escrow is unsettled; the readback sees the settlement.
            life.rpc.states[life.channel_id] = (900, DEPOSIT, 0)
            life.rpc.sent.append(params[0])
            return "0x" + f"{len(life.rpc.sent):064x}"

        life.rpc.overrides["eth_sendRawTransaction"] = settled_after_send
        supervision = await life.supervise(settlement_schedule=ResolvedSettlementSchedule(units=1))
        assert outcomes(supervision) == ["settled"] and supervision.settled == 1
        assert (await life.channel()).settled_on_chain == 900
        # Not due again.
        again = await life.supervise(settlement_schedule=ResolvedSettlementSchedule(units=1))
        assert outcomes(again) == ["open"]


class TestBatches:
    async def test_reports_records_it_cannot_supervise(self, life: Supervised) -> None:
        other = "0x" + "ee" * 32
        supervision = await life.supervise(channel_ids=[other, life.channel_id], chain_id=4217)
        assert outcomes(supervision) == ["missing", "failed"]
        assert "not 4217" in str(supervision.channels[1].error)
        assert supervision.failed == 1 and not supervision.complete
        await life.update(backend="contract")
        assert outcomes(await life.supervise(chain_id=CHAIN_ID)) == ["missing"]

    async def test_store_and_rpc_failures_fail_their_channels(
        self, life: Supervised, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tests.test_session_chain import fail

        life.rpc.overrides["eth_call"] = fail("node down")
        assert outcomes(await life.supervise()) == ["failed"]

        life.rpc.overrides["eth_call"] = lambda params: (
            "0x" + abi.encode_get_channel_states_batch([])[10:]
        )
        assert outcomes(await life.supervise()) == ["failed"]

        async def broken(channel_id: str) -> Any:
            raise RuntimeError("store down")

        store = life.store
        monkeypatch.setattr(store, "get_channel", broken)
        supervision = await life.supervise(store=store)
        assert outcomes(supervision) == ["failed"]

    async def test_batches_sync_and_async_channel_lists(self, life: Supervised) -> None:
        ids = [life.channel_id, "0x" + "e1" * 32, "0x" + "e2" * 32]
        supervision = await life.supervise(channel_ids=ids, batch_size=2)
        # Each batch reports its missing records before reading the escrow for the rest.
        assert outcomes(supervision) == ["missing", "open", "missing"]
        exact = await life.supervise(channel_ids=ids[:2], batch_size=2)
        assert outcomes(exact) == ["missing", "open"]

        async def stream() -> AsyncIterator[str]:
            for channel_id in ids:
                yield channel_id

        supervision = await life.supervise(channel_ids=stream(), batch_size=2)
        assert sorted(outcomes(supervision)) == ["missing", "missing", "open"]
        assert supervision.supervised == 3

    async def test_requires_a_pinned_block(self, life: Supervised) -> None:
        life.block = None
        with pytest.raises(RuntimeError, match="no block"):
            await life.supervise()
        life.block = {"number": BLOCK, "timestamp": None}
        with pytest.raises(ValueError, match="hex quantity"):
            await life.supervise()
