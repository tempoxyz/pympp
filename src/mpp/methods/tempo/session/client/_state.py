"""Client credential planning for TIP-1034 sessions (mppx session/client/CredentialState.ts).

Resolves a ``tempo/session`` challenge into typed data, chooses the next
credential (open a channel, recover one, sign the next cumulative voucher, or a
manual top-up/voucher/close), and executes that plan against the channel store.
Also holds mppx's deposit sizing rules (session/client/Runtime.ts).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from mpp import Challenge
from mpp._typing import is_dict
from mpp._units import parse_units
from mpp.methods.tempo.client import (
    AutoSwap,
    _find_auto_swap_calls,  # pyright: ignore[reportPrivateUsage]
)
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._channel import (
    resolve_authorized_signer as resolve_descriptor_signer,
)
from mpp.methods.tempo.session._protocol import (
    SESSION_PROTOCOL_V2,
    ChannelDescriptor,
    OpenPayload,
    TopUpPayload,
)
from mpp.methods.tempo.session.client._ops import (
    SessionCredentialPayload,
    create_close_payload,
    create_open_payload,
    create_top_up_payload,
    create_voucher_payload,
    is_same_address,
    read_optional_address,
    resolve_authorized_signer,
    resolve_escrow,
)
from mpp.methods.tempo.session.client._store import (
    ChannelEntry,
    ChannelStore,
    channel_key,
    delete_channel,
    entry_key,
    persist_channel,
    store_get,
)

if TYPE_CHECKING:
    import httpx

    from mpp.methods.tempo.account import TempoAccount

SessionAction = Literal["open", "topUp", "voucher", "close"]


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionContext:
    """Low-level context for a session credential (mppx ``SessionContext``).

    Omit ``action`` for automatic open/recover/voucher management. Amount fields
    are human-readable (parsed with the method's decimals); their ``_raw``
    variants are raw token units and take precedence. ``auto_swap`` overrides the
    method's auto-swap for this credential (``False`` disables it).
    """

    action: SessionAction | None = None
    channel_id: str | None = None
    cumulative_amount: str | None = None
    cumulative_amount_raw: str | None = None
    transaction: str | None = None
    descriptor: ChannelDescriptor | None = None
    additional_deposit: str | None = None
    additional_deposit_raw: str | None = None
    deposit_raw: str | None = None
    auto_swap: bool | AutoSwap | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionSnapshot:
    """The parts of a server ``sessionSnapshot`` the client uses to resume a channel."""

    channel_id: str
    descriptor: ChannelDescriptor
    accepted_cumulative: int
    required_cumulative: int
    spent: int
    deposit: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ChallengeContext:
    """Resolved challenge fields used to plan a client-side session credential."""

    amount: int
    challenge: Challenge
    chain_id: int
    rpc_url: str
    escrow: str
    key: str
    payee: str
    token: str
    fee_payer: bool | None = None
    fee_token: str | None = None
    operator: str | None = None
    snapshot: SessionSnapshot | None = None
    suggested_deposit_raw: str | None = None


@dataclass(slots=True, kw_only=True)
class ChannelSink:
    """Channel persistence and update notification for credential results."""

    store: ChannelStore
    notify_update: Callable[[ChannelEntry], None]


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialPlan:
    """The next credential operation the client should execute.

    ``type`` is ``open`` (no reusable channel), ``recover`` (resume a channel
    from a caller descriptor or server snapshot), ``voucher`` (raise the cached
    channel's cumulative amount) or ``manual`` (an explicit context action).
    """

    type: Literal["open", "recover", "voucher", "manual"]
    account: TempoAccount
    resolved: ChallengeContext
    entry: ChannelEntry | None = None
    context: SessionContext | None = None
    decimals: int = 6
    max_deposit: int | None = None


# ──────────────────────────────────────────────────────────────────
# Deposit sizing (mppx session/client/Runtime.ts)
# ──────────────────────────────────────────────────────────────────


def assert_voucher_within_local_limit(
    cumulative_amount: int, max_voucher_cumulative: int | None
) -> None:
    """Reject a cumulative authorization above the local ``max_deposit``."""
    if max_voucher_cumulative is None or cumulative_amount <= max_voucher_cumulative:
        return
    raise ValueError(
        f"requested voucher amount {cumulative_amount} exceeds local maxDeposit "
        f"{max_voucher_cumulative}"
    )


def assert_within_max_deposit(cumulative_amount: int, max_deposit: int | None) -> None:
    """Enforce the optional client-side maximum cumulative voucher authorization."""
    assert_voucher_within_local_limit(cumulative_amount, max_deposit)


def resolve_opening_deposit(
    *,
    request_amount: int,
    max_deposit: int | None = None,
    suggested_deposit_raw: str | None = None,
    context_deposit_raw: str | None = None,
) -> int:
    """The deposit for a new channel.

    A context deposit wins (at least the request amount); otherwise the server's
    ``suggestedDeposit`` when larger than the request amount, capped at ``max_deposit``.
    """
    assert_within_max_deposit(request_amount, max_deposit)
    if context_deposit_raw is not None:
        deposit = int(context_deposit_raw)
        if deposit < request_amount:
            raise ValueError(f"opening deposit {deposit} below request amount {request_amount}")
        return deposit
    suggested = int(suggested_deposit_raw) if suggested_deposit_raw is not None else None
    proposed = suggested if suggested is not None and suggested > request_amount else request_amount
    if max_deposit is not None:
        return min(proposed, max_deposit)
    return proposed


def resolve_automatic_top_up(
    *,
    deposit: int,
    required_cumulative: int,
    max_deposit: int | None = None,
    suggested_deposit: int | None = None,
    top_up_amount: int | None = None,
) -> int:
    """A bounded refill: ``top_up_amount``, else ``suggestedDeposit``, else the shortfall.

    Never less than the shortfall and never past ``max_deposit``; zero when the
    deposit already covers ``required_cumulative``.
    """
    if required_cumulative <= deposit:
        return 0
    assert_voucher_within_local_limit(required_cumulative, max_deposit)
    shortfall = required_cumulative - deposit
    if top_up_amount is not None:
        preferred = top_up_amount
    elif suggested_deposit is not None:
        preferred = suggested_deposit
    else:
        preferred = shortfall
    proposed = max(preferred, shortfall)
    if max_deposit is None:
        return proposed
    return min(proposed, max_deposit - deposit)


# ──────────────────────────────────────────────────────────────────
# Challenge resolution
# ──────────────────────────────────────────────────────────────────


def is_tip1034_session_challenge(challenge: Challenge) -> bool:
    """Whether ``challenge`` is a ``tempo/session`` challenge for the TIP-1034 precompile (v2)."""
    if challenge.method != "tempo" or challenge.intent != "session":
        return False
    details = challenge.request.get("methodDetails")
    return is_dict(details) and details.get("sessionProtocol") == SESSION_PROTOCOL_V2


def assert_allowed_chain_id(allowed_chain_ids: Sequence[int] | None, chain_id: int | None) -> None:
    """Reject disallowed or unknown payment chains when an allowlist is configured."""
    if allowed_chain_ids is not None and (chain_id is None or chain_id not in allowed_chain_ids):
        shown = chain_id if chain_id is not None else "unknown"
        raise ValueError(f"Chain ID not allowed: {shown}.")


def _read_int(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("expected an integer amount")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ValueError("expected an integer amount")


def read_session_snapshot(details: dict[str, Any]) -> SessionSnapshot | None:
    """The challenge's ``sessionSnapshot``, or ``None`` when absent or malformed."""
    snapshot = details.get("sessionSnapshot")
    if not is_dict(snapshot):
        return None
    try:
        return SessionSnapshot(
            channel_id=str(snapshot["channelId"]),
            descriptor=ChannelDescriptor.from_wire(snapshot["descriptor"]),
            accepted_cumulative=_read_int(snapshot["acceptedCumulative"]),
            required_cumulative=_read_int(snapshot["requiredCumulative"]),
            spent=_read_int(snapshot["spent"]),
            deposit=_read_int(snapshot["deposit"]),
        )
    except (KeyError, ValueError):
        return None


ResolveRpc = Callable[[int | None], Awaitable[tuple[str, int]]]
"""Returns ``(rpc_url, chain_id)`` for a requested chain (or the default when ``None``)."""


async def resolve_challenge_context(
    challenge: Challenge,
    *,
    resolve_rpc: ResolveRpc,
    allow_custom_escrow: bool = False,
    escrow_override: str | None = None,
    allowed_chain_ids: Sequence[int] | None = None,
) -> ChallengeContext:
    """Resolve raw challenge fields into the data credential planning needs."""
    request = challenge.request
    details_value = request.get("methodDetails")
    details: dict[str, Any] = details_value if is_dict(details_value) else {}
    raw_chain_id = details.get("chainId")
    challenge_chain_id = (
        raw_chain_id
        if isinstance(raw_chain_id, int) and not isinstance(raw_chain_id, bool)
        else None
    )
    if challenge_chain_id is not None or (allowed_chain_ids is not None and not allowed_chain_ids):
        assert_allowed_chain_id(allowed_chain_ids, challenge_chain_id)
    requested = challenge_chain_id
    if requested is None and allowed_chain_ids is not None and len(allowed_chain_ids) == 1:
        requested = allowed_chain_ids[0]
    rpc_url, chain_id = await resolve_rpc(requested)
    if requested is not None and chain_id != requested:
        raise ValueError(f"Chain ID mismatch: expected {requested}, got {chain_id}.")
    assert_allowed_chain_id(allowed_chain_ids, chain_id)

    escrow = resolve_escrow(request, escrow_override, allow_custom_escrow)
    payee = read_optional_address(request.get("recipient"))
    if payee is None:
        raise ValueError("tempo session challenge missing recipient")
    token = read_optional_address(request.get("currency"))
    if token is None:
        raise ValueError("tempo session challenge missing currency")
    amount = request.get("amount")
    if not isinstance(amount, str):
        raise ValueError("tempo session challenge missing amount")
    fee_payer = details.get("feePayer")
    suggested = request.get("suggestedDeposit")
    return ChallengeContext(
        amount=int(amount),
        challenge=challenge,
        chain_id=chain_id,
        rpc_url=rpc_url,
        escrow=escrow,
        key=channel_key(payee=payee, token=token, escrow=escrow, chain_id=chain_id),
        payee=payee,
        token=token,
        fee_payer=fee_payer if isinstance(fee_payer, bool) else None,
        fee_token=read_optional_address(details.get("feeToken")),
        operator=read_optional_address(details.get("operator")),
        snapshot=read_session_snapshot(details),
        suggested_deposit_raw=suggested if isinstance(suggested, str) else None,
    )


# ──────────────────────────────────────────────────────────────────
# Recovery
# ──────────────────────────────────────────────────────────────────


def _assert_reusable_descriptor(
    *,
    channel_id: str | None,
    descriptor: ChannelDescriptor,
    expected_channel_id: str,
    payee: str,
    payer: str,
    authorized_signer: str,
    token: str,
) -> None:
    if channel_id and channel_id.lower() != expected_channel_id.lower():
        raise ValueError("context channelId does not match descriptor")
    if not is_same_address(descriptor.payee, payee):
        raise ValueError("context descriptor payee does not match challenge")
    if not is_same_address(descriptor.token, token):
        raise ValueError("context descriptor token does not match challenge")
    if not is_same_address(descriptor.payer, payer):
        raise ValueError("context descriptor payer does not match account")
    if not is_same_address(resolve_descriptor_signer(descriptor), authorized_signer):
        raise ValueError("context descriptor authorizedSigner does not match account")


async def resolve_reusable_channel(
    *,
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    resolved: ChallengeContext,
    channel_id: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[str, chain.ChannelState]:
    """Validate a descriptor against the challenge and read its open on-chain state."""
    expected_channel_id = compute_channel_id(
        descriptor, chain_id=resolved.chain_id, escrow=resolved.escrow
    )
    _assert_reusable_descriptor(
        channel_id=channel_id,
        descriptor=descriptor,
        expected_channel_id=expected_channel_id,
        payee=resolved.payee,
        payer=account.address,
        authorized_signer=resolve_authorized_signer(account),
        token=resolved.token,
    )
    state = await chain.get_channel_state(
        resolved.rpc_url, expected_channel_id, escrow=resolved.escrow, client=client
    )
    if state.deposit == 0:
        raise ValueError(
            f"Channel {expected_channel_id} cannot be reused (closed or not found on-chain)."
        )
    if state.close_requested_at != 0:
        raise ValueError(f"Channel {expected_channel_id} cannot be reused (pending close request).")
    return expected_channel_id, state


def can_sign_descriptor(account: TempoAccount, descriptor: ChannelDescriptor) -> bool:
    """Whether ``account`` is the descriptor's payer and voucher authority."""
    if not is_same_address(account.address, descriptor.payer):
        return False
    return is_same_address(
        resolve_authorized_signer(account), resolve_descriptor_signer(descriptor)
    )


AmountField = Literal["additional_deposit", "cumulative_amount"]


def parse_optional_context_amount(
    context: SessionContext, decimals: int, field: AmountField
) -> int | None:
    """A context amount in raw units, preferring the ``_raw`` field."""
    if field == "additional_deposit":
        raw, amount = context.additional_deposit_raw, context.additional_deposit
    else:
        raw, amount = context.cumulative_amount_raw, context.cumulative_amount
    if raw:
        return int(raw)
    if amount:
        return parse_units(amount, decimals)
    return None


def require_context_amount(
    context: SessionContext, decimals: int, field: AmountField, action: str
) -> int:
    """A required context amount in raw units."""
    amount = parse_optional_context_amount(context, decimals, field)
    if amount is None:
        name = "additionalDeposit" if field == "additional_deposit" else "cumulativeAmount"
        raise ValueError(f"{name} required for {action} action")
    return amount


def _recover_context(
    context: SessionContext | None, snapshot: SessionSnapshot | None
) -> SessionContext | None:
    descriptor = (context.descriptor if context else None) or (
        snapshot.descriptor if snapshot else None
    )
    if descriptor is None:
        return None
    base = context or SessionContext()
    return SessionContext(
        action=base.action,
        channel_id=base.channel_id or (snapshot.channel_id if snapshot else None),
        cumulative_amount=base.cumulative_amount,
        cumulative_amount_raw=base.cumulative_amount_raw,
        transaction=base.transaction,
        descriptor=descriptor,
        additional_deposit=base.additional_deposit,
        additional_deposit_raw=base.additional_deposit_raw,
        deposit_raw=base.deposit_raw,
        auto_swap=base.auto_swap,
    )


def resolve_recovered_cumulative(
    *,
    context: SessionContext,
    decimals: int,
    request_amount: int,
    settled: int,
    snapshot: SessionSnapshot | None = None,
) -> int:
    """A voucher boundary that covers the resumed request."""
    if snapshot is not None:
        return max(
            snapshot.accepted_cumulative,
            snapshot.required_cumulative,
            snapshot.spent + request_amount,
            settled,
            0,
        )
    contextual = parse_optional_context_amount(context, decimals, "cumulative_amount")
    if contextual is not None:
        return contextual + request_amount
    return settled + request_amount


# ──────────────────────────────────────────────────────────────────
# Planning and execution
# ──────────────────────────────────────────────────────────────────


def plan_credential(
    *,
    account: TempoAccount,
    entry: ChannelEntry | None,
    resolved: ChallengeContext,
    context: SessionContext | None = None,
    decimals: int = 6,
    max_deposit: int | None = None,
) -> CredentialPlan:
    """Choose the next credential from the cached channel and optional context."""
    if context is not None and context.action is not None:
        if context.descriptor is None:
            raise ValueError("descriptor required for TIP-1034 session action")
        return CredentialPlan(
            type="manual", account=account, resolved=resolved, context=context, decimals=decimals
        )
    if entry is None and context is not None and context.channel_id and not context.descriptor:
        raise ValueError("descriptor required to reuse TIP-1034 channel")
    recover = _recover_context(context, resolved.snapshot)
    if (
        entry is None
        and recover is not None
        and recover.descriptor is not None
        and can_sign_descriptor(account, recover.descriptor)
    ):
        return CredentialPlan(
            type="recover",
            account=account,
            resolved=resolved,
            context=recover,
            decimals=decimals,
            max_deposit=max_deposit,
        )
    if entry is not None and entry.opened and can_sign_descriptor(account, entry.descriptor):
        return CredentialPlan(
            type="voucher",
            account=account,
            resolved=resolved,
            entry=entry,
            max_deposit=max_deposit,
        )
    return CredentialPlan(
        type="open", account=account, resolved=resolved, context=context, max_deposit=max_deposit
    )


async def _store_channel_entry(sink: ChannelSink, entry: ChannelEntry) -> None:
    """Persist ``entry`` (or remove it once closed) and notify observers."""
    if entry.opened:
        await persist_channel(sink.store, entry)
    else:
        await delete_channel(sink.store, entry_key(entry))
    sink.notify_update(entry)


def read_credential_cumulative_amount(payload: SessionCredentialPayload) -> int | None:
    """A payload's cumulative authorization, when its action carries one."""
    if isinstance(payload, TopUpPayload):
        return None
    return int(payload.cumulative_amount)


async def _apply_cumulative(sink: ChannelSink, key: str, payload: SessionCredentialPayload) -> None:
    cumulative = read_credential_cumulative_amount(payload)
    if cumulative is None:
        return
    entry = await store_get(sink.store, key)
    if entry is None or entry.channel_id.lower() != payload.channel_id.lower():
        return
    entry = entry.copy(cumulative_amount=max(entry.cumulative_amount, cumulative))
    if payload.action == "close":
        entry.opened = False
    await _store_channel_entry(sink, entry)


def resolve_auto_swap(value: bool | AutoSwap | None) -> AutoSwap | None:
    """The auto-swap options for ``value``: defaults for ``True``, none when off."""
    if value is True:
        return AutoSwap()
    return value or None


async def resolve_auto_swap_calls(
    auto_swap: AutoSwap | None,
    *,
    account: TempoAccount,
    amount_out: int,
    resolved: ChallengeContext,
    client: httpx.AsyncClient | None = None,
) -> list[tuple[str, str]]:
    """Approve and swap calls buying the channel token the payer lacks (mppx
    ``resolveAutoSwapCalls``); none when auto-swap is off or the balance suffices."""
    if auto_swap is None:
        return []
    calls, _ = await _find_auto_swap_calls(
        auto_swap,
        account=account.address,
        amount_out=amount_out,
        token_out=resolved.token,
        rpc_url=resolved.rpc_url,
        client=client,
    )
    return calls


async def execute_credential_plan(
    plan: CredentialPlan,
    sink: ChannelSink,
    *,
    client: httpx.AsyncClient | None = None,
    auto_swap: AutoSwap | None = None,
) -> SessionCredentialPayload:
    """Execute ``plan`` and return the credential payload; updates the store.

    With ``auto_swap``, an open or manual top-up the payer cannot fund in the
    channel token first buys it on the stablecoin DEX in the same transaction.
    """
    resolved = plan.resolved
    account = plan.account
    if plan.type == "open":
        deposit = resolve_opening_deposit(
            request_amount=resolved.amount,
            max_deposit=plan.max_deposit,
            suggested_deposit_raw=resolved.suggested_deposit_raw,
            context_deposit_raw=plan.context.deposit_raw if plan.context else None,
        )
        payload = await create_open_payload(
            account,
            rpc_url=resolved.rpc_url,
            chain_id=resolved.chain_id,
            deposit=deposit,
            initial_amount=resolved.amount,
            payee=resolved.payee,
            token=resolved.token,
            escrow=resolved.escrow,
            operator=resolved.operator,
            fee_payer=resolved.fee_payer,
            fee_token=resolved.fee_token,
            prefix_calls=await resolve_auto_swap_calls(
                auto_swap, account=account, amount_out=deposit, resolved=resolved, client=client
            ),
            client=client,
        )
        await _store_channel_entry(
            sink,
            ChannelEntry(
                channel_id=payload.channel_id,
                cumulative_amount=resolved.amount,
                deposit=deposit,
                descriptor=ChannelDescriptor.from_wire(payload.descriptor),
                escrow=resolved.escrow,
                chain_id=resolved.chain_id,
                opened=True,
            ),
        )
        return payload

    if plan.type == "recover":
        assert plan.context is not None and plan.context.descriptor is not None
        descriptor = plan.context.descriptor
        channel_id, state = await resolve_reusable_channel(
            account=account,
            descriptor=descriptor,
            resolved=resolved,
            channel_id=plan.context.channel_id,
            client=client,
        )
        cumulative = resolve_recovered_cumulative(
            context=plan.context,
            decimals=plan.decimals,
            request_amount=resolved.amount,
            settled=state.settled,
            snapshot=resolved.snapshot,
        )
        if cumulative > state.deposit:
            raise ValueError("recovered voucher amount exceeds on-chain channel deposit")
        assert_within_max_deposit(cumulative, plan.max_deposit)
        payload = create_voucher_payload(
            account, descriptor, cumulative, resolved.chain_id, resolved.escrow
        )
        current = await store_get(sink.store, resolved.key)
        await _store_channel_entry(
            sink,
            ChannelEntry(
                channel_id=channel_id,
                cumulative_amount=cumulative,
                deposit=state.deposit,
                descriptor=descriptor,
                escrow=resolved.escrow,
                chain_id=resolved.chain_id,
                opened=True,
                uncertain_top_up=bool(
                    current is not None
                    and current.channel_id == channel_id
                    and current.uncertain_top_up
                ),
            ),
        )
        return payload

    if plan.type == "voucher":
        assert plan.entry is not None
        entry = plan.entry
        cumulative = entry.cumulative_amount + resolved.amount
        assert_within_max_deposit(cumulative, plan.max_deposit)
        payload = create_voucher_payload(
            account, entry.descriptor, cumulative, resolved.chain_id, resolved.escrow
        )
        await _store_channel_entry(sink, entry.copy(cumulative_amount=cumulative))
        return payload

    payload = await _manual(plan, client=client, auto_swap=auto_swap)
    await _apply_cumulative(sink, resolved.key, payload)
    return payload


async def _manual(
    plan: CredentialPlan, *, client: httpx.AsyncClient | None, auto_swap: AutoSwap | None
) -> SessionCredentialPayload:
    context = plan.context
    assert context is not None and context.descriptor is not None
    resolved, account, decimals = plan.resolved, plan.account, plan.decimals
    descriptor = context.descriptor
    channel_id = compute_channel_id(descriptor, chain_id=resolved.chain_id, escrow=resolved.escrow)
    _assert_reusable_descriptor(
        channel_id=context.channel_id,
        descriptor=descriptor,
        expected_channel_id=channel_id,
        payee=resolved.payee,
        payer=account.address,
        authorized_signer=resolve_authorized_signer(account),
        token=resolved.token,
    )
    if context.action == "open":
        if not context.transaction:
            raise ValueError("transaction required for open action")
        cumulative = require_context_amount(context, decimals, "cumulative_amount", "open")
        voucher = create_voucher_payload(
            account, descriptor, cumulative, resolved.chain_id, resolved.escrow
        )
        return OpenPayload.model_validate(
            {
                "channelId": channel_id,
                "transaction": context.transaction,
                "signature": voucher.signature,
                "descriptor": descriptor.to_wire(),
                "cumulativeAmount": str(cumulative),
                "authorizedSigner": descriptor.authorized_signer,
            }
        )
    if context.action == "topUp":
        additional = require_context_amount(context, decimals, "additional_deposit", "topUp")
        if context.transaction:
            return TopUpPayload.model_validate(
                {
                    "channelId": channel_id,
                    "transaction": context.transaction,
                    "descriptor": descriptor.to_wire(),
                    "additionalDeposit": str(additional),
                }
            )
        return await create_top_up_payload(
            account,
            descriptor,
            additional,
            rpc_url=resolved.rpc_url,
            chain_id=resolved.chain_id,
            fee_payer=resolved.fee_payer,
            escrow=resolved.escrow,
            prefix_calls=await resolve_auto_swap_calls(
                auto_swap, account=account, amount_out=additional, resolved=resolved, client=client
            ),
            fee_token=resolved.fee_token,
            client=client,
        )
    if context.action == "voucher":
        return create_voucher_payload(
            account,
            descriptor,
            require_context_amount(context, decimals, "cumulative_amount", "voucher"),
            resolved.chain_id,
            resolved.escrow,
        )
    return create_close_payload(
        account,
        descriptor,
        require_context_amount(context, decimals, "cumulative_amount", "close"),
        resolved.chain_id,
        resolved.escrow,
    )
