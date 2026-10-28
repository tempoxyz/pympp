"""Close supervision for payer close requests on idle channels (mppx ``CloseSupervisor.ts``).

After a payer requests a close on-chain, the escrow lets it withdraw the whole deposit once
its close grace period (900 seconds on Tempo) ends, so run :func:`supervise_closes` from a
scheduled job well within that period, for example every minute.
"""

from __future__ import annotations

from collections.abc import AsyncIterable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Literal

from mpp._typing import is_dict, is_list
from mpp.errors import VerificationFailedError
from mpp.methods.tempo.session import _abi as abi
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._protocol import ZERO_ADDRESS
from mpp.methods.tempo.session.server._schedule import ResolvedSettlementSchedule
from mpp.methods.tempo.session.server._settlement import (
    OnSessionSettlement,
    OnSessionSettlementFailure,
    SessionSettlementContext,
    SessionSettlementFailureContext,
    assert_settlement_sender,
    emit_session_settlement,
    maybe_settle_scheduled,
    report_session_settlement_failure,
    resolve_channel_store,
)
from mpp.methods.tempo.session.server._store import (
    ChannelState,
    ChannelStore,
    finalize_closed_channel_state,
    is_precompile_state,
    keep_greater,
    merge_active_on_chain_state,
    reconcile_expired_pending_close,
    resolve_close_capture_amount,
)

if TYPE_CHECKING:
    import httpx

    from mpp.methods.tempo.account import TempoAccount

__all__ = [
    "DEFAULT_BATCH_SIZE",
    "DEFAULT_CLOSE_SEARCH_MARGIN_BLOCKS",
    "DEFAULT_LOG_BLOCK_RANGE",
    "CloseSupervision",
    "CloseSupervisionOutcome",
    "SupervisedChannel",
    "supervise_closes",
]

DEFAULT_BATCH_SIZE = 50
"""Channels whose escrow states one call reads."""
DEFAULT_LOG_BLOCK_RANGE = 100_000
"""Widest log query ``rpc.tempo.xyz`` accepts."""
DEFAULT_CLOSE_SEARCH_MARGIN_BLOCKS = 2_000
"""Blocks searched before the previous complete supervision for a channel's close event."""

CloseSupervisionOutcome = Literal[
    "open",
    "settled",
    "closing",
    "cancelled",
    "closed",
    "unrecovered",
    "finalized",
    "missing",
    "failed",
]
"""What one supervision did with a channel (mppx ``CloseSupervisionOutcome``).

``open``: no close request (or not open yet at the pinned block). ``settled``: open and settled
on ``settlement_schedule``. ``closing``: close requested with nothing above the settled amount to
capture. ``cancelled``: a recorded close request was cancelled on-chain. ``closed``: a payee close
captured the spend, or the deposit left with it paid. ``unrecovered``: the deposit left paying
less than the spend. ``finalized``: already finalized. ``missing``: no precompile channel record.
``failed``: a later supervision retries it.
"""


@dataclass(frozen=True, slots=True)
class SupervisedChannel:
    """One channel's supervision outcome."""

    channel_id: str
    outcome: CloseSupervisionOutcome
    error: BaseException | None = None
    tx_hash: str | None = None


@dataclass(slots=True)
class CloseSupervision:
    """Result of one :func:`supervise_closes` run.

    Pass ``block`` as ``previous_block`` to the next run once ``complete``. Channels whose outcome
    is ``closed``, ``unrecovered``, ``finalized`` or ``missing`` need no further supervision.
    """

    block: int
    timestamp: int
    complete: bool = False
    supervised: int = 0
    cancelled: int = 0
    closed: int = 0
    failed: int = 0
    settled: int = 0
    unrecovered: int = 0
    channels: list[SupervisedChannel] = field(default_factory=list[SupervisedChannel])


@dataclass(frozen=True, slots=True, kw_only=True)
class _Options:
    store: ChannelStore
    rpc_url: str
    http_client: httpx.AsyncClient | None
    account: TempoAccount | None
    candidate_fee_tokens: Sequence[str] | None
    fee_payer: TempoAccount | None
    fee_payer_policy: Mapping[str, int] | None
    fee_token: str | None
    on_session_settlement: OnSessionSettlement | None
    on_session_settlement_failure: OnSessionSettlementFailure | None
    settlement_schedule: ResolvedSettlementSchedule | None
    close_search_margin_blocks: int
    log_block_range: int
    previous_block: int | None
    pinned_block: int
    pinned_timestamp: int


def _hex_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16)
    raise ValueError("expected a hex quantity")


async def supervise_closes(
    *,
    channel_ids: Iterable[str] | AsyncIterable[str],
    store: Any,
    rpc_url: str,
    account: TempoAccount | None = None,
    http_client: httpx.AsyncClient | None = None,
    chain_id: int | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    close_search_margin_blocks: int = DEFAULT_CLOSE_SEARCH_MARGIN_BLOCKS,
    log_block_range: int = DEFAULT_LOG_BLOCK_RANGE,
    previous_block: int | None = None,
    settlement_schedule: ResolvedSettlementSchedule | None = None,
    candidate_fee_tokens: Sequence[str] | None = None,
    fee_payer: TempoAccount | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    on_session_settlement: OnSessionSettlement | None = None,
    on_session_settlement_failure: OnSessionSettlementFailure | None = None,
) -> CloseSupervision:
    """Answer payer close requests on channels the server is not otherwise touching.

    Reads every channel's escrow state at one pinned block, in batches. A close request is
    answered with a payee close capturing ``max(spent, settled)`` (bounded by the highest
    voucher and the deposit), which pays the accepted charges and refunds the rest. A deposit
    that already left the escrow is finalized from its ``ChannelClosed`` event, searched in
    pages of ``log_block_range`` blocks. A close request cancelled on-chain reopens the channel.
    With ``settlement_schedule`` (raw units), open channels whose spend crossed it are settled.

    ``channel_ids``: the channels to supervise. A channel store cannot list its channels, so the
    caller keeps their IDs. ``account`` is the payee or operator that sends closes and
    settlements; ``chain_id``, when given, must match each channel's.
    """
    channel_store = resolve_channel_store(store)
    # A read pinned to this block fails on a node that has not reached it, instead of
    # answering with older state that would hide a close request.
    block = await chain._rpc(  # pyright: ignore[reportPrivateUsage]
        rpc_url, "eth_getBlockByNumber", ["latest", False], http_client
    )
    if not is_dict(block):
        raise RuntimeError("eth_getBlockByNumber returned no block")
    pinned_block = _hex_int(block.get("number"))
    pinned_timestamp = _hex_int(block.get("timestamp"))
    supervision = CloseSupervision(block=pinned_block, timestamp=pinned_timestamp)
    options = _Options(
        store=channel_store,
        rpc_url=rpc_url,
        http_client=http_client,
        account=account,
        candidate_fee_tokens=candidate_fee_tokens,
        fee_payer=fee_payer,
        fee_payer_policy=fee_payer_policy,
        fee_token=fee_token,
        on_session_settlement=on_session_settlement,
        on_session_settlement_failure=on_session_settlement_failure,
        settlement_schedule=settlement_schedule,
        close_search_margin_blocks=close_search_margin_blocks,
        log_block_range=log_block_range,
        previous_block=previous_block,
        pinned_block=pinned_block,
        pinned_timestamp=pinned_timestamp,
    )

    def report(
        channel_id: str,
        outcome: CloseSupervisionOutcome,
        *,
        error: BaseException | None = None,
        tx_hash: str | None = None,
    ) -> None:
        supervision.supervised += 1
        if outcome == "cancelled":
            supervision.cancelled += 1
        elif outcome == "closed":
            supervision.closed += 1
        elif outcome == "failed":
            supervision.failed += 1
        elif outcome == "settled":
            supervision.settled += 1
        elif outcome == "unrecovered":
            supervision.unrecovered += 1
        supervision.channels.append(SupervisedChannel(channel_id, outcome, error, tx_hash))

    async def supervise_batch(ids: list[str]) -> None:
        live: list[ChannelState] = []
        for channel_id in ids:
            try:
                channel = await channel_store.get_channel(channel_id)
            except Exception as error:
                report(channel_id, "failed", error=error)
                continue
            if channel is None or not is_precompile_state(channel):
                report(channel_id, "missing")
            elif channel.finalized:
                report(channel_id, "finalized")
            elif chain_id is not None and chain_id != channel.chain_id:
                report(
                    channel_id,
                    "failed",
                    error=ValueError(f"Channel is on chain {channel.chain_id}, not {chain_id}."),
                )
            else:
                live.append(channel)
        by_escrow: dict[str, list[ChannelState]] = {}
        for channel in live:
            by_escrow.setdefault(channel.escrow_contract.lower(), []).append(channel)
        for members in by_escrow.values():
            try:
                states = await chain.get_channel_states_batch(
                    rpc_url,
                    [member.channel_id for member in members],
                    escrow=members[0].escrow_contract,
                    block=pinned_block,
                    client=http_client,
                )
            except Exception as error:
                for member in members:
                    report(member.channel_id, "failed", error=error)
                continue
            for index, channel in enumerate(members):
                if index >= len(states):
                    report(channel.channel_id, "failed", error=ValueError("Escrow state missing."))
                    continue
                try:
                    outcome, tx_hash = await _supervise_channel(options, channel, states[index])
                    report(channel.channel_id, outcome, tx_hash=tx_hash)
                except Exception as error:
                    # A close that landed before this failure is found by its event next time.
                    report(channel.channel_id, "failed", error=error)

    batch: list[str] = []
    if isinstance(channel_ids, AsyncIterable):
        async for channel_id in channel_ids:
            batch.append(channel_id)
            if len(batch) >= batch_size:
                await supervise_batch(batch)
                batch = []
    else:
        for channel_id in channel_ids:
            batch.append(channel_id)
            if len(batch) >= batch_size:
                await supervise_batch(batch)
                batch = []
    if batch:
        await supervise_batch(batch)
    supervision.complete = supervision.failed == 0
    return supervision


async def _supervise_channel(
    options: _Options, channel: ChannelState, state: chain.ChannelState
) -> tuple[CloseSupervisionOutcome, str | None]:
    store = options.store
    channel_id = channel.channel_id
    if state.deposit == 0:
        # A complete supervision read every listed channel still supervised, so a channel read
        # open lost its deposit after the later of that read and the previous complete run.
        since = channel.close_supervised_from_block
        previous = options.previous_block
        if since is None:
            from_block = (
                previous if previous is not None else options.pinned_block
            ) - options.close_search_margin_blocks
        else:
            from_block = previous if previous is not None and previous > since else since
        paid = await _find_settled_to_payee(options, channel, max(from_block, 0))
        if paid is None:
            # An open landing after the pinned block also reads as no deposit.
            if since is None:
                return "open", None
            raise VerificationFailedError(
                "channel left the escrow without a ChannelClosed event in its search range"
            )

        def finalize(current: ChannelState | None) -> ChannelState | None:
            if current is None or current.finalized:
                return current
            return replace(
                current,
                close_requested_at=0,
                deposit=0,
                finalized=True,
                settled_on_chain=keep_greater(current.settled_on_chain, paid),
            )

        finalized = await store.update_channel(channel_id, finalize)
        spent = finalized.spent if finalized is not None else channel.spent
        return ("closed" if paid >= spent else "unrecovered"), None
    if channel.close_supervised_from_block is None:
        pinned = options.pinned_block
        await store.update_channel(
            channel_id,
            lambda current: (
                replace(current, close_supervised_from_block=pinned)
                if current is not None and current.close_supervised_from_block is None
                else current
            ),
        )
    if state.close_requested_at == 0:
        if channel.close_requested_at == 0:
            return await _settle_due(options, channel)
        # A pinned read without a request means the payer cancelled it, unless the record holds
        # a server close that may still land: those expire before they are cleared.
        cleared: list[ChannelState | None] = [None]

        def reconcile(current: ChannelState | None) -> ChannelState | None:
            cleared[0] = reconcile_expired_pending_close(
                current=current, now=options.pinned_timestamp, state=state
            )
            return cleared[0]

        await store.update_channel(channel_id, reconcile)
        result = cleared[0]
        if result is not None and result.close_requested_at == 0 and not result.finalized:
            return "cancelled", None
        return "open", None

    # A pending close stops charges and credits, so the spend this close captures stays fixed.
    def merge(current: ChannelState | None) -> ChannelState | None:
        if current is None or current.finalized:
            return current
        on_chain = merge_active_on_chain_state(current, state)
        return replace(
            current,
            close_requested_at=on_chain.close_requested_at,
            deposit=on_chain.deposit,
            settled_on_chain=on_chain.settled_on_chain,
        )

    closing = await store.update_channel(channel_id, merge)
    if closing is None or closing.finalized or not is_precompile_state(closing):
        return "finalized", None
    return await _close_at_spend(options, closing, state)


async def _settle_due(
    options: _Options, channel: ChannelState
) -> tuple[CloseSupervisionOutcome, str | None]:
    if options.settlement_schedule is None:
        return "open", None
    tx_hash = await maybe_settle_scheduled(
        channel=channel,
        schedule=options.settlement_schedule,
        store=options.store,
        account=options.account,
        rpc_url=options.rpc_url,
        http_client=options.http_client,
        fee_payer=options.fee_payer,
        fee_payer_policy=options.fee_payer_policy,
        fee_token=options.fee_token,
        on_session_settlement=options.on_session_settlement,
        on_session_settlement_failure=options.on_session_settlement_failure,
    )
    return ("settled", tx_hash) if tx_hash else ("open", None)


async def _close_at_spend(
    options: _Options, channel: ChannelState, state: chain.ChannelState
) -> tuple[CloseSupervisionOutcome, str | None]:
    channel_id = channel.channel_id
    try:
        voucher = channel.highest_voucher
        if voucher is None or channel.descriptor is None:
            raise VerificationFailedError("no voucher to close with")
        capture = resolve_close_capture_amount(
            cumulative_amount=voucher.cumulative_amount,
            on_chain_deposit=state.deposit,
            on_chain_settled=state.settled,
            spent=channel.spent,
        )
        if capture <= state.settled:
            return "closing", None
        account = options.account
        assert_settlement_sender(
            operation="close",
            channel_id=channel_id,
            operator=channel.operator or ZERO_ADDRESS,
            payee=channel.payee,
            sender=account.address if account is not None else None,
        )
        assert account is not None
        tx_hash = await chain.close_on_chain(
            options.rpc_url,
            account,
            channel.descriptor,
            voucher.cumulative_amount,
            capture,
            voucher.signature,
            escrow=channel.escrow_contract,
            fee_payer=options.fee_payer,
            fee_payer_policy=options.fee_payer_policy,
            fee_token=options.fee_token,
            candidate_fee_tokens=options.candidate_fee_tokens or [channel.token],
            client=options.http_client,
        )
        receipt = await chain.wait_for_successful_receipt(
            options.rpc_url, tx_hash, client=options.http_client
        )
        closed = chain.get_channel_event(receipt, "ChannelClosed", channel_id)
        settled_to_payee = int(closed["settledToPayee"])
        refunded_to_payer = int(closed["refundedToPayer"])
        if settled_to_payee > capture or settled_to_payee + refunded_to_payer > state.deposit:
            raise VerificationFailedError("ChannelClosed amounts do not match state")
        await options.store.update_channel(
            channel_id,
            lambda current: finalize_closed_channel_state(
                capture_amount=settled_to_payee,
                channel_id=channel_id,
                cumulative_amount=voucher.cumulative_amount,
                current=current,
                signature=voucher.signature,
            ),
        )
        await emit_session_settlement(
            options.on_session_settlement,
            SessionSettlementContext(
                tx_hash=tx_hash,
                channel_id=channel_id,
                trigger="close",
                amount=settled_to_payee,
                delta=settled_to_payee - state.settled,
            ),
        )
        return "closed", tx_hash
    except Exception as error:
        await report_session_settlement_failure(
            options.on_session_settlement_failure,
            SessionSettlementFailureContext(
                chain_id=channel.chain_id, channel_id=channel_id, error=error, trigger="close"
            ),
        )
        raise


async def _find_settled_to_payee(
    options: _Options, channel: ChannelState, from_block: int
) -> int | None:
    """Amount paid to the payee when the channel closed within the range, if it did."""
    step = options.log_block_range
    start = from_block
    while start <= options.pinned_block:
        end = min(start + step - 1, options.pinned_block)
        logs = await chain._rpc(  # pyright: ignore[reportPrivateUsage]
            options.rpc_url,
            "eth_getLogs",
            [
                {
                    "address": channel.escrow_contract,
                    "topics": [abi.EVENT_TOPICS["ChannelClosed"], channel.channel_id],
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                }
            ],
            options.http_client,
        )
        for log in logs if is_list(logs) else []:
            if not is_dict(log) or log.get("removed"):
                continue
            topics = log.get("topics")
            if not is_list(topics):
                continue
            event = abi.decode_event([str(t) for t in topics], str(log.get("data", "0x")))
            if (
                event is not None
                and event.name == "ChannelClosed"
                and str(event.args["channelId"]).lower() == channel.channel_id.lower()
            ):
                return int(event.args["settledToPayee"])
        start += step
    return None
