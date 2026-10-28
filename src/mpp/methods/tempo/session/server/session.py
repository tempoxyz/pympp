"""Server-side TIP-1034 session payment method (mppx ``server/Session.ts``).

``session(...)`` returns a pympp :class:`~mpp.server.method.ServerMethod` handling the full
TIP20EscrowChannel lifecycle (open, voucher, top-up, close) over request/response flows: each
content request pays its route amount from the channel's accepted vouchers, and management
requests (top-up, close, and open/voucher on non-content requests) get ``204`` with a session
receipt. Module-level :func:`charge` and :func:`credit` adjust a channel's spend outside a route.

Not ported: SSE/WebSocket metering, bootstrap/snapshot recovery, sponsorship limits,
``voucherStateMaxAge`` (vouchers are always checked against a fresh chain read) and
``chargeOnAcceptance``.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, cast

from mpp import Receipt
from mpp._units import parse_units
from mpp._validation import Validation
from mpp.errors import VerificationFailedError
from mpp.methods.tempo.session.protocol import (
    SessionReceipt,
    definition,
    serialize_session_receipt,
)
from mpp.methods.tempo.session.server.request_state import (
    capture_request_probe,
    resolve_credential_verification_context,
    resolve_session_payment_request,
    respond_to_session_credential,
)
from mpp.methods.tempo.session.server.schedule import (
    SettlementSchedule,
    resolve_settlement_schedule,
)
from mpp.methods.tempo.session.server.settlement import (
    OnSessionSettlement,
    OnSessionSettlementFailure,
    apply_verified_http_accounting,
    charge_session_channel,
    ignore_retryable_settlement_failure,
    maybe_settle_scheduled,
    resolve_channel_store,
    should_apply_verified_http_accounting,
)
from mpp.methods.tempo.session.server.store import (
    ChannelState,
    CreditResult,
    credit_channel,
    from_store,
    normalize_channel_id,
)
from mpp.methods.tempo.session.server.verification import (
    CredentialContext,
    broadcast_credential_payload,
    require_session_credential_payload,
    validate_credential_payload,
)
from mpp.server.method import (
    RequestContext,
    RespondContext,
    ServerMethod,
    ValidateContext,
    VerifyContext,
)

if TYPE_CHECKING:
    import httpx

    from mpp.methods import CanOfferFn, PaymentSuccessHandler
    from mpp.methods.tempo.account import TempoAccount
    from mpp.server.http import Response
    from mpp.store import Store

__all__ = ["SessionPaymentReceipt", "charge", "credit", "session"]

logger = logging.getLogger(__name__)

_warned_fallback_store = False


def _fallback_store() -> Store:
    """The in-memory channel store used without a configured one, warning once per process."""
    from mpp.store import MemoryStore

    global _warned_fallback_store
    if not _warned_fallback_store:
        _warned_fallback_store = True
        logger.warning(
            "tempo.session has no store configured and is using an in-memory store. Channel "
            "state (accepted vouchers and spend) is scoped to this process, so another worker "
            "or replica, or this one after a restart, cannot charge or close its channels. "
            "Pass a shared compare-and-set store (e.g. mpp.stores.RedisStore) via "
            "tempo.session(store=...) when running more than one instance."
        )
    return MemoryStore()


@dataclass(frozen=True, slots=True)
class SessionPaymentReceipt(Receipt):
    """A receipt whose ``Payment-Receipt`` header is exactly mppx's session receipt JSON.

    ``session`` holds the session fields; ``extensions`` mirrors them (camelCase) for code that
    reads a generic :class:`~mpp.Receipt`.
    """

    session: SessionReceipt | None = None

    def to_payment_receipt(self) -> str:
        if self.session is None:
            return Receipt.to_payment_receipt(self)
        return serialize_session_receipt(self.session)

    @classmethod
    def from_session(cls, session: SessionReceipt) -> SessionPaymentReceipt:
        """Wrap a session receipt for the engine."""
        wire = session.to_wire()
        return cls(
            status="success",
            timestamp=datetime.fromisoformat(session.timestamp.replace("Z", "+00:00")),
            reference=session.reference,
            method="tempo",
            extensions={
                key: value
                for key, value in wire.items()
                if key not in ("method", "status", "timestamp", "reference")
            },
            session=session,
        )


def _reusable_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    """Binds a reusable challenge to its route and channel terms, not its quoted amount."""
    details: Any = request.get("methodDetails")
    method_details: Mapping[str, Any] = (
        cast(Mapping[str, Any], details) if isinstance(details, Mapping) else {}
    )
    return {
        "chainId": method_details.get("chainId"),
        "currency": request.get("currency"),
        "escrowContract": method_details.get("escrowContract"),
        "operator": method_details.get("operator"),
        "recipient": request.get("recipient"),
        "sessionProtocol": method_details.get("sessionProtocol"),
        "unitType": request.get("unitType"),
    }


def session(
    *,
    account: TempoAccount | None = None,
    recipient: str | None = None,
    currency: str | None = None,
    decimals: int = 6,
    chain_id: int | None = None,
    rpc_url: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    escrow_contract: str | None = None,
    store: Store | None = None,
    fee_payer: TempoAccount | Literal[True] | None = None,
    fee_payer_policy: Mapping[str, int] | None = None,
    fee_token: str | None = None,
    min_voucher_delta: str | None = None,
    settlement_schedule: SettlementSchedule | None = None,
    on_session_settlement: OnSessionSettlement | None = None,
    on_session_settlement_failure: OnSessionSettlementFailure | None = None,
    channel_state_ttl: int = 5_000,
    reusable_challenges: bool = False,
    amount: str | None = None,
    unit_type: str | None = None,
    suggested_deposit: str | None = None,
    operator: str | None = None,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
) -> ServerMethod:
    """Create the server-side Tempo session method (mppx ``tempo.session``).

    Routes take ``amount`` (decimal string, the price of one content request) and ``unit_type``,
    and optionally ``suggested_deposit``, ``min_voucher_delta``, ``recipient``, ``currency``,
    ``operator``, ``escrow_contract``, ``chain_id`` and ``fee_payer`` (False turns sponsorship off).

    Args:
        account: Payee account: receives payments and sends server settle/close transactions.
        recipient: Payee address, when it differs from ``account`` (default: its address).
        currency: TIP-20 token (default: the chain's default currency).
        decimals: Token decimals for route amounts (default 6).
        chain_id: Tempo chain ID (default: the RPC's, or mainnet without ``rpc_url``).
        rpc_url: RPC endpoint (default: the chain's).
        http_client: HTTP client for RPC calls, owned by the caller.
        escrow_contract: Escrow advertised to clients (default: the TIP-1034 precompile).
        store: Channel store. Use a :class:`~mpp.store.CompareAndSetStore` (MemoryStore,
            RedisStore, SQLiteStore) shared by every instance, so channel updates are
            linearizable; defaults to a per-process in-memory store.
        fee_payer: Account that sponsors open/top-up and server settle/close fees; ``True``
            makes ``account`` the fee payer.
        fee_payer_policy: Overrides of the fee-payer policy (``max_gas``, ...).
        fee_token: Fee token clients use for open/top-up and the server for settle/close.
        min_voucher_delta: Minimum voucher increase (decimal string, default "0").
        settlement_schedule: Server-owned automatic settlement cadence.
        on_session_settlement: Called after a settlement or close transaction confirms.
        on_session_settlement_failure: Called when a scheduled settlement or close fails.
        channel_state_ttl: Milliseconds validation trusts a cached on-chain read (default 5000).
        reusable_challenges: Let a challenge pay later requests to the same route until it
            expires: it is bound to the route and channel terms, not the amount it quoted,
            and each request is charged its own price.
        amount: Default route amount.
        unit_type: Default unit type (such as ``"request"``).
        suggested_deposit: Default suggested deposit (decimal string).
        operator: Default channel operator clients encode in new channels.
        can_offer: Decides whether to advertise an offer for a wire request.
        on_payment_success: Called with each successful session payment event.
    """
    from mpp.methods.tempo._defaults import (
        CHAIN_ID,
        default_currency_for_chain,
        rpc_url_for_chain,
    )

    if chain_id is None and rpc_url is None:
        chain_id = CHAIN_ID
    resolved_rpc_url = rpc_url or rpc_url_for_chain(chain_id or CHAIN_ID)
    resolved_currency = currency or default_currency_for_chain(chain_id)
    resolved_recipient = recipient or (account.address if account is not None else None)
    resolved_fee_payer: TempoAccount | None = (
        account if fee_payer is True else fee_payer if fee_payer is not None else None
    )
    if fee_payer is True and account is None:
        raise ValueError("fee_payer=True requires an account")
    schedule = resolve_settlement_schedule(settlement_schedule, decimals)
    channel_store = from_store(store if store is not None else _fallback_store())
    last_on_chain_verified: dict[str, int] = {}
    chain_ids: list[int] = [chain_id] if chain_id is not None else []

    async def resolve_chain_id() -> int:
        if not chain_ids:
            from mpp.methods.tempo.session import chain

            result = await chain._rpc(  # pyright: ignore[reportPrivateUsage]
                resolved_rpc_url, "eth_chainId", [], http_client
            )
            chain_ids.append(int(str(result), 16))
        return chain_ids[0]

    defaults = {
        key: value
        for key, value in {
            "amount": amount,
            "currency": resolved_currency,
            "decimals": decimals,
            "operator": operator,
            "recipient": resolved_recipient,
            "suggested_deposit": suggested_deposit,
            "unit_type": unit_type,
        }.items()
        if value is not None
    }

    async def resolve_request(context: RequestContext) -> dict[str, Any]:
        request = context.request
        if request.get("recipient") is None:
            raise ValueError("tempo.session() needs a recipient: pass account or recipient")
        resolved = resolve_session_payment_request(
            request=request,
            chain_id=await resolve_chain_id(),
            default_fee_payer=resolved_fee_payer,
            parameter_escrow_contract=escrow_contract,
            fee_token=fee_token,
        )
        resolved.setdefault("decimals", decimals)
        return resolved

    def credential_context(
        context: VerifyContext, payload: Any, **overrides: Any
    ) -> CredentialContext:
        verification = resolve_credential_verification_context(
            challenge=context.challenge,
            decimals=decimals,
            fee_payer=resolved_fee_payer,
            min_voucher_delta=min_voucher_delta,
        )
        return CredentialContext(
            challenge=context.challenge,
            payload=payload,
            chain_id=verification.chain_id,
            escrow=verification.escrow,
            rpc_url=resolved_rpc_url,
            store=channel_store,
            account=account,
            http_client=http_client,
            channel_state_ttl=channel_state_ttl,
            credential_source=context.credential.source,
            expected_operator=verification.method_details.operator,
            fee_payer=verification.fee_payer,
            fee_payer_policy=fee_payer_policy,
            fee_token=verification.method_details.fee_token,
            last_on_chain_verified=last_on_chain_verified,
            min_voucher_delta=verification.min_voucher_delta,
            on_session_settlement=on_session_settlement,
            on_session_settlement_failure=on_session_settlement_failure,
            **overrides,
        )

    async def validate(context: ValidateContext) -> Validation:
        payload = require_session_credential_payload(context.credential.payload)
        credential = replace(context.credential, payload=payload.to_wire())
        if context.operation == "broadcast" and payload.action == "voucher":
            # A broadcast voucher is checked against the stored channel by its acceptance.
            details: dict[str, Any] = {
                "action": payload.action,
                "channelId": normalize_channel_id(payload.channel_id),
            }
        else:
            validation = await validate_credential_payload(
                credential_context(
                    context, payload, allow_pending_close=context.operation == "broadcast"
                )
            )
            details = {"action": validation.action, "channelId": validation.channel_id}
        return Validation(
            credential=credential,
            details=details,
            intent="session",
            request=dict(context.challenge.request),
        )

    def route_amount(context: VerifyContext) -> int:
        """The price of this request: the route's amount, not the challenge's quote."""
        request = context.request
        value = request.get("amount")
        if isinstance(value, str):
            return parse_units(value, int(request.get("decimals", decimals)))
        quoted = context.challenge.request.get("amount")
        if isinstance(quoted, str) and quoted.isdigit():
            return int(quoted)
        raise VerificationFailedError("missing request amount")

    async def settle_charged(channel: ChannelState) -> str | None:
        try:
            return await maybe_settle_scheduled(
                channel=channel,
                schedule=schedule,
                store=channel_store,
                account=account,
                rpc_url=resolved_rpc_url,
                http_client=http_client,
                fee_payer=resolved_fee_payer,
                fee_payer_policy=fee_payer_policy,
                fee_token=fee_token,
                on_session_settlement=on_session_settlement,
                on_session_settlement_failure=on_session_settlement_failure,
            )
        except Exception as error:
            # A failed scheduled settlement is reported and retried by the next one; the
            # charged request stays served because the payer's voucher covers the charge.
            return ignore_retryable_settlement_failure(error)

    async def broadcast(context: VerifyContext) -> Receipt:
        payload = require_session_credential_payload(context.credential.payload)
        probe = capture_request_probe(context.input) if context.input is not None else None
        receipt = await broadcast_credential_payload(
            credential_context(
                context,
                payload,
                require_voucher_advance=should_apply_verified_http_accounting(
                    request=probe, payload_action=payload.action
                ),
            )
        )

        async def charge_channel(channel_id: str, request_amount: int) -> ChannelState:
            return await charge_session_channel(channel_store, channel_id, request_amount)

        charged = await apply_verified_http_accounting(
            receipt=receipt,
            request=probe,
            payload_action=payload.action,
            request_amount=lambda: route_amount(context),
            charge=charge_channel,
            settle_charged=settle_charged,
        )
        return SessionPaymentReceipt.from_session(charged)

    def respond(context: RespondContext) -> Response | None:
        payload = require_session_credential_payload(context.credential.payload)
        return respond_to_session_credential(payload_action=payload.action, request=context.input)

    return ServerMethod(
        method=definition,
        validate=validate,
        broadcast=broadcast,
        resolve_request=resolve_request,
        can_offer=can_offer,
        on_payment_success=on_payment_success,
        defaults=defaults,
        respond=respond,
        stable_binding=_reusable_binding if reusable_challenges else None,
    )


async def charge(
    store: Any,
    channel_id: str,
    amount: int,
    *,
    idempotency_key: str | None = None,
    retention: int | None = None,
) -> ChannelState:
    """Charge ``amount`` (raw units) against a channel's accepted vouchers, outside a route.

    With ``idempotency_key`` the channel is charged at most once per key: a retry with the same
    key and amount returns the channel without charging again; the same key with another
    amount raises :class:`~mpp.methods.tempo.session.server.store.IdempotencyKeyConflictError`.
    ``retention`` (ms, default a day) must cover every retry.

    Raises:
        InsufficientBalanceError: The accepted vouchers do not cover the charge.
        ChannelClosedError: The channel is missing, closing or finalized.
    """
    return await charge_session_channel(
        resolve_channel_store(store),
        channel_id,
        amount,
        idempotency_key=idempotency_key,
        retention=retention,
    )


async def credit(
    store: Any,
    channel_id: str,
    amount: int,
    *,
    idempotency_key: str,
    retention: int | None = None,
    units: int = 0,
) -> CreditResult:
    """Return an unused ``amount`` to a channel's spend at most once per idempotency key.

    The first outcome for a key is final. A credit is ``declined`` when the channel is closing
    or finalized, or when it would take ``spent`` below zero or below what settled, or may still
    settle, on-chain; the caller then refunds another way. ``unknown`` reports a store write
    that failed and may have committed: retry with the same key.
    """
    return await credit_channel(
        resolve_channel_store(store),
        channel_id,
        amount,
        idempotency_key=idempotency_key,
        retention=retention,
        units=units,
    )
