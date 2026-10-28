"""Session credential validation and state transitions (mppx ``CredentialVerification.ts``).

:func:`validate_credential_payload` checks a credential without changing payment state;
:func:`broadcast_credential_payload` broadcasts its transaction (open, top-up, close) or accepts
its voucher and applies the state transition to the channel store.

Also holds the voucher helpers the channel store leaves to verification:
:func:`load_precompile_channel`, :func:`validate_voucher` and :func:`verify_and_accept_voucher`.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, cast

from pydantic import BaseModel

from mpp._defaults import DEFAULT_TIMEOUT
from mpp.errors import VerificationFailedError
from mpp.methods.tempo.session import chain
from mpp.methods.tempo.session.channel import compute_channel_id, resolve_authorized_signer
from mpp.methods.tempo.session.protocol import (
    ZERO_ADDRESS,
    ChannelDescriptor,
    ClosePayload,
    OpenPayload,
    SessionCredentialPayload,
    SessionPayload,
    SessionReceipt,
    SignedVoucher,
    TopUpPayload,
    VoucherPayload,
    create_session_receipt,
    uint96,
)
from mpp.methods.tempo.session.server.request_state import get_challenge_payment_fields
from mpp.methods.tempo.session.server.schedule import ResolvedSettlementSchedule
from mpp.methods.tempo.session.server.settlement import (
    OnSessionSettlement,
    OnSessionSettlementFailure,
    SessionSettlementContext,
    SessionSettlementFailureContext,
    assert_settlement_sender,
    emit_session_settlement,
    maybe_settle_scheduled,
    report_session_settlement_failure,
)
from mpp.methods.tempo.session.server.store import (
    PENDING_CLOSE_VALIDITY_SECONDS,
    AmountExceedsDepositError,
    ChannelClosedError,
    ChannelNotFoundError,
    ChannelState,
    ChannelStore,
    DeltaTooSmallError,
    InsufficientBalanceError,
    InvalidSignatureError,
    OnChainChannelState,
    VoucherValidation,
    accept_voucher_state_update,
    finalize_closed_channel_state,
    is_precompile_state,
    keep_greater,
    mark_pending_close,
    normalize_channel_id,
    open_channel_state,
    reconcile_expired_pending_close,
    top_up_channel_state,
)
from mpp.methods.tempo.session.voucher import (
    parse_voucher_from_payload,
    verify_close_authorization,
    verify_voucher,
)

if TYPE_CHECKING:
    import httpx

    from mpp import Challenge
    from mpp.methods.tempo.account import TempoAccount

__all__ = [
    "CredentialContext",
    "CredentialValidation",
    "assert_credential_source_can_spend",
    "assert_open_credential_covers_request",
    "assert_same_descriptor",
    "authorized_signer",
    "broadcast_credential_payload",
    "load_precompile_channel",
    "require_session_credential_payload",
    "validate_channel_descriptor",
    "validate_channel_state",
    "validate_credential_payload",
    "validate_voucher",
    "verify_and_accept_voucher",
]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _same(a: str, b: str) -> bool:
    return a.lower() == b.lower()


# --------------------------------------------------------------------------------------------
# Descriptor and state checks
# --------------------------------------------------------------------------------------------


def authorized_signer(descriptor: ChannelDescriptor) -> str:
    """The effective voucher signer of a descriptor: the payer when unset."""
    return resolve_authorized_signer(descriptor)


def assert_same_descriptor(a: ChannelDescriptor, b: ChannelDescriptor) -> None:
    """Check two descriptors identify the same channel."""
    if not (
        _same(a.payer, b.payer)
        and _same(a.payee, b.payee)
        and _same(a.operator, b.operator)
        and _same(a.token, b.token)
        and _same(a.authorized_signer, b.authorized_signer)
        and _same(a.salt, b.salt)
        and _same(a.expiring_nonce_hash, b.expiring_nonce_hash)
    ):
        raise VerificationFailedError("credential descriptor does not match stored channel")


def validate_channel_descriptor(
    descriptor: ChannelDescriptor,
    channel_id: str,
    chain_id: int,
    escrow: str,
    recipient: str,
    currency: str,
    expected_operator: str | None = None,
) -> None:
    """Check a descriptor against its channel ID, the server's destination and token."""
    computed = compute_channel_id(descriptor, chain_id=chain_id, escrow=escrow)
    if not _same(computed, channel_id):
        raise VerificationFailedError("channel descriptor does not match channelId")
    if not _same(descriptor.payee, recipient):
        raise VerificationFailedError("channel descriptor payee does not match server destination")
    if not _same(descriptor.token, currency):
        raise VerificationFailedError("channel descriptor token does not match server token")
    if expected_operator is not None and not _same(descriptor.operator, expected_operator):
        raise VerificationFailedError("channel descriptor operator does not match server operator")


def validate_channel_state(state: OnChainChannelState, amount: int | None = None) -> None:
    """Check on-chain channel state before accepting or charging a credential."""
    if state.deposit == 0:
        raise ChannelNotFoundError("channel not funded on-chain")
    if state.close_requested_at != 0:
        raise ChannelClosedError("channel has a pending close request")
    if amount is not None and state.deposit - state.settled < amount:
        raise InsufficientBalanceError(
            "channel available balance insufficient for requested amount"
        )


def assert_open_credential_covers_request(
    *, cumulative_amount: int, open_deposit: int, request_amount: int
) -> None:
    """Check an opening channel covers the route's requested payment."""
    if open_deposit < request_amount:
        raise VerificationFailedError("open deposit is less than request amount")
    if cumulative_amount < request_amount:
        raise VerificationFailedError("voucher amount is less than request amount")


def _read_source_address(source: str | None, chain_id: int) -> str:
    prefix = f"did:pkh:eip155:{chain_id}:"
    if not source or not source.startswith(prefix):
        raise VerificationFailedError("credential source does not match channel")
    address = source[len(prefix) :]
    if not _ADDRESS_RE.fullmatch(address):
        raise VerificationFailedError("invalid credential source")
    return address


def assert_credential_source_can_spend(
    *, chain_id: int, channel: ChannelState, source: str | None
) -> None:
    """Check the credential source is the channel's payer or authorized signer."""
    address = _read_source_address(source, chain_id)
    if _same(address, channel.payer) or _same(address, channel.authorized_signer):
        return
    raise VerificationFailedError(
        "credential source does not match channel payer or authorized signer"
    )


# --------------------------------------------------------------------------------------------
# Payload reading
# --------------------------------------------------------------------------------------------

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")
_RAW_AMOUNT_RE = re.compile(r"^[0-9]+$")


def _invalid(field_name: str) -> VerificationFailedError:
    return VerificationFailedError(f"invalid session credential {field_name}")


def _read(value: Any, pattern: re.Pattern[str], field_name: str) -> str:
    if isinstance(value, str) and pattern.fullmatch(value):
        return value
    raise _invalid(field_name)


def _read_descriptor(value: Any) -> dict[str, str]:
    if value is None:
        raise VerificationFailedError("descriptor required for TIP-1034 session action")
    if not isinstance(value, dict):
        raise _invalid("payload")
    candidate = cast(dict[str, Any], value)
    return {
        "payer": _read(candidate.get("payer"), _ADDRESS_RE, "descriptor.payer"),
        "payee": _read(candidate.get("payee"), _ADDRESS_RE, "descriptor.payee"),
        "operator": _read(candidate.get("operator"), _ADDRESS_RE, "descriptor.operator"),
        "token": _read(candidate.get("token"), _ADDRESS_RE, "descriptor.token"),
        "salt": _read(candidate.get("salt"), _HASH_RE, "descriptor.salt"),
        "authorizedSigner": _read(
            candidate.get("authorizedSigner"), _ADDRESS_RE, "descriptor.authorizedSigner"
        ),
        "expiringNonceHash": _read(
            candidate.get("expiringNonceHash"), _HASH_RE, "descriptor.expiringNonceHash"
        ),
    }


def _payload_dict(payload: Any) -> dict[str, Any]:
    if isinstance(payload, SessionPayload):
        payload = payload.root
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(mode="json", by_alias=True, exclude_none=True)
    if not isinstance(payload, dict):
        raise _invalid("payload")
    return cast(dict[str, Any], payload)


def require_session_credential_payload(payload: Any) -> SessionCredentialPayload:
    """Validate every action-specific field of a session credential payload, as mppx does.

    Accepts the engine's parsed payload model or its JSON. Amounts must be raw integers and
    the descriptor is required; the channel ID is lowercased.
    """
    candidate = _payload_dict(payload)
    action = candidate.get("action")
    if action not in ("open", "topUp", "voucher", "close"):
        raise VerificationFailedError("invalid session credential action")
    channel_id = normalize_channel_id(_read(candidate.get("channelId"), _HASH_RE, "channelId"))
    if action == "open":
        if candidate.get("type") != "transaction":
            raise _invalid("transaction type")
        data: dict[str, Any] = {
            "action": "open",
            "type": "transaction",
            "channelId": channel_id,
            "transaction": _read(candidate.get("transaction"), _HEX_RE, "transaction"),
            "signature": _read(candidate.get("signature"), _HEX_RE, "signature"),
            "descriptor": _read_descriptor(candidate.get("descriptor")),
            "cumulativeAmount": _read(
                candidate.get("cumulativeAmount"), _RAW_AMOUNT_RE, "cumulativeAmount"
            ),
        }
        if candidate.get("authorizedSigner") is not None:
            data["authorizedSigner"] = _read(
                candidate.get("authorizedSigner"), _ADDRESS_RE, "authorizedSigner"
            )
        return OpenPayload.model_validate(data)
    if action == "topUp":
        if candidate.get("type") != "transaction":
            raise _invalid("transaction type")
        return TopUpPayload.model_validate(
            {
                "action": "topUp",
                "type": "transaction",
                "channelId": channel_id,
                "transaction": _read(candidate.get("transaction"), _HEX_RE, "transaction"),
                "descriptor": _read_descriptor(candidate.get("descriptor")),
                "additionalDeposit": _read(
                    candidate.get("additionalDeposit"), _RAW_AMOUNT_RE, "additionalDeposit"
                ),
            }
        )
    if action == "voucher":
        return VoucherPayload.model_validate(
            {
                "action": "voucher",
                "channelId": channel_id,
                "descriptor": _read_descriptor(candidate.get("descriptor")),
                "cumulativeAmount": _read(
                    candidate.get("cumulativeAmount"), _RAW_AMOUNT_RE, "cumulativeAmount"
                ),
                "signature": _read(candidate.get("signature"), _HEX_RE, "signature"),
            }
        )
    return ClosePayload.model_validate(
        {
            "action": "close",
            "channelId": channel_id,
            "descriptor": _read_descriptor(candidate.get("descriptor")),
            "cumulativeAmount": _read(
                candidate.get("cumulativeAmount"), _RAW_AMOUNT_RE, "cumulativeAmount"
            ),
            "signature": _read(candidate.get("signature"), _HEX_RE, "signature"),
            "closeSignature": _read(candidate.get("closeSignature"), _HEX_RE, "closeSignature"),
        }
    )


def _descriptor(payload: SessionCredentialPayload) -> ChannelDescriptor:
    descriptor = payload.channel_descriptor()
    if descriptor is None:
        raise VerificationFailedError("descriptor required for TIP-1034 session action")
    return descriptor


def _amount(value: str) -> int:
    try:
        return uint96(int(value))
    except ValueError as error:
        raise VerificationFailedError(str(error)) from error


# --------------------------------------------------------------------------------------------
# Voucher helpers (mppx ChannelStore.ts loadPrecompileChannel / validateVoucher /
# verifyAndAcceptVoucher)
# --------------------------------------------------------------------------------------------


async def load_precompile_channel(
    *,
    store: ChannelStore,
    channel_id: str,
    descriptor: ChannelDescriptor,
    chain_id: int,
    escrow: str,
    validate_descriptor: bool = False,
) -> ChannelState:
    """Load a stored precompile channel and check the credential's descriptor matches it.

    Raises:
        ChannelNotFoundError: No channel is stored under ``channel_id``.
        VerificationFailedError: It is not precompile-backed or the descriptor differs.
    """
    channel = await store.get_channel(channel_id)
    if channel is None:
        raise ChannelNotFoundError("channel not found")
    if not is_precompile_state(channel) or channel.descriptor is None:
        raise VerificationFailedError("channel is not precompile-backed")
    assert_same_descriptor(descriptor, channel.descriptor)
    if validate_descriptor:
        validate_channel_descriptor(
            descriptor, channel_id, chain_id, escrow, channel.payee, channel.token
        )
    return channel


def validate_voucher(
    *,
    channel: ChannelState,
    channel_state: OnChainChannelState,
    chain_id: int,
    escrow: str,
    min_voucher_delta: int,
    voucher: SignedVoucher,
) -> VoucherValidation:
    """Verify a cumulative voucher against channel state without changing persisted state.

    ``already_accepted`` is set for a voucher equal to the highest accepted one.
    """
    validate_channel_state(channel_state)
    if voucher.cumulative_amount > channel_state.deposit:
        raise AmountExceedsDepositError("voucher amount exceeds on-chain deposit")
    if voucher.cumulative_amount < channel.highest_voucher_amount:
        raise VerificationFailedError(
            "voucher cumulativeAmount must be strictly greater than highest accepted voucher"
        )
    if not verify_voucher(escrow, chain_id, voucher, channel.authorized_signer):
        raise InvalidSignatureError("invalid voucher signature")
    if voucher.cumulative_amount <= channel_state.settled:
        raise VerificationFailedError("voucher cumulativeAmount is below on-chain settled amount")
    if voucher.cumulative_amount == channel.highest_voucher_amount:
        return VoucherValidation(already_accepted=True)
    delta = voucher.cumulative_amount - channel.highest_voucher_amount
    if delta < min_voucher_delta:
        raise DeltaTooSmallError(f"voucher delta {delta} below minimum {min_voucher_delta}")
    return VoucherValidation(already_accepted=False)


async def verify_and_accept_voucher(
    *,
    store: ChannelStore,
    challenge_id: str,
    channel: ChannelState,
    voucher: SignedVoucher,
    channel_state: OnChainChannelState,
    chain_id: int,
    escrow: str,
    min_voucher_delta: int,
    require_advance: bool = False,
    verified_at: int | None = None,
) -> SessionReceipt:
    """Verify a voucher and record it as the channel's highest; returns the session receipt.

    With ``require_advance`` a voucher must add new funds (a content request pays with it).
    """
    validation = validate_voucher(
        channel=channel,
        channel_state=channel_state,
        chain_id=chain_id,
        escrow=escrow,
        min_voucher_delta=min_voucher_delta,
        voucher=voucher,
    )
    if validation.already_accepted and require_advance:
        raise DeltaTooSmallError("voucher does not add new funds for this request")
    if validation.already_accepted:
        return create_session_receipt(
            challenge_id=challenge_id,
            channel_id=voucher.channel_id,
            accepted_cumulative=channel.highest_voucher_amount,
            spent=channel.spent,
            units=channel.units,
        )

    def accept(current: ChannelState | None) -> ChannelState | None:
        if (
            require_advance
            and current is not None
            and voucher.cumulative_amount <= current.highest_voucher_amount
        ):
            raise DeltaTooSmallError("voucher does not add new funds for this request")
        return accept_voucher_state_update(
            channel_state=channel_state, current=current, voucher=voucher, verified_at=verified_at
        )

    updated = await store.update_channel(voucher.channel_id, accept)
    if updated is None:
        raise ChannelNotFoundError("channel not found")
    return create_session_receipt(
        challenge_id=challenge_id,
        channel_id=voucher.channel_id,
        accepted_cumulative=updated.highest_voucher_amount,
        spent=updated.spent,
        units=updated.units,
    )


# --------------------------------------------------------------------------------------------
# Credential context
# --------------------------------------------------------------------------------------------


@dataclass(kw_only=True)
class CredentialContext:
    """Inputs to validate or broadcast one session credential.

    ``last_on_chain_verified`` (channel ID to Unix ms of the last successful on-chain read) is
    shared across a method's credentials; ``channel_state_ttl`` (ms) bounds how long a
    non-mutating validation trusts it.
    """

    challenge: Challenge
    payload: SessionCredentialPayload
    chain_id: int
    escrow: str
    rpc_url: str
    store: ChannelStore
    account: TempoAccount | None = None
    http_client: httpx.AsyncClient | None = None
    channel_state_ttl: int = 5_000
    credential_source: str | None = None
    expected_operator: str | None = None
    fee_payer: TempoAccount | None = None
    fee_payer_policy: Mapping[str, int] | None = None
    fee_token: str | None = None
    last_on_chain_verified: dict[str, int] = field(default_factory=dict[str, int])
    min_voucher_delta: int = 0
    on_session_settlement: OnSessionSettlement | None = None
    on_session_settlement_failure: OnSessionSettlementFailure | None = None
    require_voucher_advance: bool = False
    allow_pending_close: bool = False


@dataclass(frozen=True, slots=True)
class CredentialValidation:
    """Result of a non-mutating credential validation."""

    action: str
    channel_id: str


def _allowed_fee_tokens(currency: str, fee_token: str | None) -> list[str]:
    """The advertised fee token, while still accepting fees paid in the channel currency."""
    if fee_token is None or _same(fee_token, currency):
        return [currency]
    return [fee_token, currency]


async def _resolve_voucher_channel_state(
    context: CredentialContext, channel_id: str, channel: ChannelState | None, *, force: bool
) -> OnChainChannelState:
    verified = context.last_on_chain_verified
    refresh = force or _now_ms() - verified.get(channel_id, 0) > context.channel_state_ttl
    if refresh:
        state = await chain.get_channel_state(
            context.rpc_url, channel_id, escrow=context.escrow, client=context.http_client
        )
        if state.close_requested_at != 0 or state.deposit == 0:
            verified.pop(channel_id, None)
        else:
            verified[channel_id] = _now_ms()
        return state
    if channel is None:
        raise ChannelNotFoundError("channel not found")
    return chain.ChannelState(
        deposit=uint96(channel.deposit),
        settled=uint96(channel.settled_on_chain),
        close_requested_at=channel.close_requested_at,
    )


# --------------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------------


async def validate_credential_payload(context: CredentialContext) -> CredentialValidation:
    """Validate every action-specific invariant of a credential without changing state."""
    payload = context.payload
    if isinstance(payload, OpenPayload):
        await _validate_open(context, payload)
    elif isinstance(payload, TopUpPayload):
        await _validate_top_up(context, payload)
    elif isinstance(payload, VoucherPayload):
        await _validate_voucher(context, payload)
    else:
        await _validate_close(context, payload)
    return CredentialValidation(payload.action, normalize_channel_id(payload.channel_id))


def _expected_operator(context: CredentialContext) -> str:
    return context.expected_operator or ZERO_ADDRESS


async def _validate_open(context: CredentialContext, payload: OpenPayload) -> None:
    request = get_challenge_payment_fields(context.challenge)
    operator = _expected_operator(context)
    cumulative = _amount(payload.cumulative_amount)
    descriptor = _descriptor(payload)
    if payload.authorized_signer is not None and not _same(
        payload.authorized_signer, descriptor.authorized_signer
    ):
        raise VerificationFailedError("credential authorizedSigner does not match descriptor")
    channel_id = normalize_channel_id(payload.channel_id)
    validate_channel_descriptor(
        descriptor,
        channel_id,
        context.chain_id,
        context.escrow,
        request.recipient,
        request.currency,
        operator,
    )
    validated = chain.validate_open_credential_transaction(
        serialized_transaction=payload.transaction,
        chain_id=context.chain_id,
        escrow_contract=context.escrow,
        expected_authorized_signer=descriptor.authorized_signer,
        expected_channel_id=channel_id,
        expected_currency=request.currency,
        expected_expiring_nonce_hash=descriptor.expiring_nonce_hash,
        expected_operator=operator,
        expected_payee=request.recipient,
        expected_payer=descriptor.payer,
        fee_payer=context.fee_payer,
        fee_payer_policy=context.fee_payer_policy,
        allowed_fee_tokens=_allowed_fee_tokens(request.currency, context.fee_token),
        challenge_expires=context.challenge.expires,
    )
    _check_open_voucher(
        context,
        channel_id=channel_id,
        cumulative=cumulative,
        signature=payload.signature,
        validated=validated,
        descriptor=descriptor,
        request_amount=request.amount,
    )
    await chain.simulate_credential_transaction(
        context.rpc_url,
        validated.transaction,
        fee_payer=context.fee_payer,
        client=context.http_client,
    )


def _check_open_voucher(
    context: CredentialContext,
    *,
    channel_id: str,
    cumulative: int,
    signature: str,
    validated: chain.ValidatedOpenTransaction,
    descriptor: ChannelDescriptor,
    request_amount: int,
) -> None:
    assert_open_credential_covers_request(
        cumulative_amount=cumulative,
        open_deposit=validated.open_deposit,
        request_amount=request_amount,
    )
    assert_same_descriptor(validated.descriptor, descriptor)
    if cumulative > validated.open_deposit:
        raise AmountExceedsDepositError("voucher amount exceeds open deposit")
    voucher = SignedVoucher(
        channel_id=channel_id, cumulative_amount=cumulative, signature=signature
    )
    if not verify_voucher(
        context.escrow, context.chain_id, voucher, authorized_signer(validated.descriptor)
    ):
        raise InvalidSignatureError("invalid voucher signature")


async def _validate_top_up(context: CredentialContext, payload: TopUpPayload) -> None:
    request = get_challenge_payment_fields(context.challenge)
    additional = _amount(payload.additional_deposit)
    descriptor = _descriptor(payload)
    channel_id = normalize_channel_id(payload.channel_id)
    validate_channel_descriptor(
        descriptor,
        channel_id,
        context.chain_id,
        context.escrow,
        request.recipient,
        request.currency,
        _expected_operator(context),
    )
    channel = await load_precompile_channel(
        store=context.store,
        channel_id=channel_id,
        descriptor=descriptor,
        chain_id=context.chain_id,
        escrow=context.escrow,
        validate_descriptor=True,
    )
    assert channel.descriptor is not None
    validated = chain.validate_top_up_credential_transaction(
        serialized_transaction=payload.transaction,
        additional_deposit=additional,
        chain_id=context.chain_id,
        descriptor=channel.descriptor,
        escrow_contract=context.escrow,
        expected_channel_id=channel_id,
        expected_currency=request.currency,
        fee_payer=context.fee_payer,
        fee_payer_policy=context.fee_payer_policy,
        allowed_fee_tokens=_allowed_fee_tokens(request.currency, context.fee_token),
        challenge_expires=context.challenge.expires,
    )
    validate_channel_state(
        await chain.get_channel_state(
            context.rpc_url, channel_id, escrow=context.escrow, client=context.http_client
        )
    )
    await chain.simulate_credential_transaction(
        context.rpc_url,
        validated.transaction,
        fee_payer=context.fee_payer,
        client=context.http_client,
    )


def _parse_voucher(payload: VoucherPayload | ClosePayload, channel_id: str) -> SignedVoucher:
    try:
        return parse_voucher_from_payload(channel_id, payload.cumulative_amount, payload.signature)
    except ValueError as error:
        raise VerificationFailedError(str(error)) from error


async def _validate_voucher(context: CredentialContext, payload: VoucherPayload) -> None:
    request = get_challenge_payment_fields(context.challenge)
    channel_id = normalize_channel_id(payload.channel_id)
    voucher = _parse_voucher(payload, channel_id)
    descriptor = _descriptor(payload)
    validate_channel_descriptor(
        descriptor,
        channel_id,
        context.chain_id,
        context.escrow,
        request.recipient,
        request.currency,
        _expected_operator(context),
    )
    channel = await load_precompile_channel(
        store=context.store,
        channel_id=channel_id,
        descriptor=descriptor,
        chain_id=context.chain_id,
        escrow=context.escrow,
        validate_descriptor=True,
    )
    assert_credential_source_can_spend(
        chain_id=context.chain_id, channel=channel, source=context.credential_source
    )
    if channel.finalized:
        raise ChannelClosedError("channel is finalized")
    state = await _resolve_voucher_channel_state(context, channel_id, channel, force=False)
    if context.allow_pending_close and state.close_requested_at != 0:
        return
    validate_voucher(
        channel=channel,
        channel_state=state,
        chain_id=context.chain_id,
        escrow=context.escrow,
        min_voucher_delta=context.min_voucher_delta,
        voucher=voucher,
    )


async def _check_close(
    context: CredentialContext, payload: ClosePayload
) -> tuple[ChannelState, chain.ChannelState, int, int, str]:
    """Shared close checks; returns (channel, state, cumulative, capture, channel_id)."""
    request = get_challenge_payment_fields(context.challenge)
    cumulative = _amount(payload.cumulative_amount)
    channel_id = normalize_channel_id(payload.channel_id)
    descriptor = _descriptor(payload)
    validate_channel_descriptor(
        descriptor,
        channel_id,
        context.chain_id,
        context.escrow,
        request.recipient,
        request.currency,
        _expected_operator(context),
    )
    channel = await load_precompile_channel(
        store=context.store,
        channel_id=channel_id,
        descriptor=descriptor,
        chain_id=context.chain_id,
        escrow=context.escrow,
    )
    authorization = SignedVoucher(
        channel_id=channel_id, cumulative_amount=cumulative, signature=payload.close_signature
    )
    if not verify_close_authorization(
        context.escrow, context.chain_id, authorization, [channel.payer, channel.authorized_signer]
    ):
        raise InvalidSignatureError("invalid close authorization signature")
    if channel.finalized:
        raise ChannelClosedError("channel is already finalized")
    state = await chain.get_channel_state(
        context.rpc_url, channel_id, escrow=context.escrow, client=context.http_client
    )
    if state.close_requested_at != 0:
        raise ChannelClosedError("channel has a pending close request")
    if state.deposit == 0 and (cumulative != 0 or channel.spent != 0):
        raise ChannelClosedError("channel deposit is zero (settled)")
    if cumulative < channel.spent:
        raise VerificationFailedError(f"close voucher amount must be >= {channel.spent} (spent)")
    if cumulative < state.settled:
        raise VerificationFailedError(
            f"close voucher amount must be >= {state.settled} (on-chain settled)"
        )
    voucher = SignedVoucher(
        channel_id=channel_id, cumulative_amount=cumulative, signature=payload.signature
    )
    if not verify_voucher(context.escrow, context.chain_id, voucher, channel.authorized_signer):
        raise InvalidSignatureError("invalid voucher signature")
    capture = uint96(max(channel.spent, state.settled))
    if capture > state.deposit:
        raise AmountExceedsDepositError("close capture amount exceeds on-chain deposit")
    return channel, state, cumulative, capture, channel_id


async def _validate_close(context: CredentialContext, payload: ClosePayload) -> None:
    channel, _, _, _, channel_id = await _check_close(context, payload)
    assert_settlement_sender(
        operation="close",
        channel_id=channel_id,
        operator=channel.operator or ZERO_ADDRESS,
        payee=channel.payee,
        sender=context.account.address if context.account is not None else None,
    )


# --------------------------------------------------------------------------------------------
# Broadcast
# --------------------------------------------------------------------------------------------

_REFRESH_ON_CHAIN_CACHE = {"open": True, "topUp": True, "voucher": False, "close": False}


async def broadcast_credential_payload(context: CredentialContext) -> SessionReceipt:
    """Broadcast a validated credential and apply its state transition; returns its receipt."""
    payload = context.payload
    if isinstance(payload, OpenPayload):
        receipt = await _handle_open(context, payload)
    elif isinstance(payload, TopUpPayload):
        receipt = await _handle_top_up(context, payload)
    elif isinstance(payload, VoucherPayload):
        receipt = await _handle_voucher(context, payload)
    else:
        receipt = await _handle_close(context, payload)
    if _REFRESH_ON_CHAIN_CACHE[payload.action]:
        context.last_on_chain_verified[receipt.channel_id] = _now_ms()
    return receipt


async def _handle_open(context: CredentialContext, payload: OpenPayload) -> SessionReceipt:
    request = get_challenge_payment_fields(context.challenge)
    operator = _expected_operator(context)
    cumulative = _amount(payload.cumulative_amount)
    descriptor = _descriptor(payload)
    if payload.authorized_signer is not None and not _same(
        payload.authorized_signer, descriptor.authorized_signer
    ):
        raise VerificationFailedError("credential authorizedSigner does not match descriptor")
    channel_id = normalize_channel_id(payload.channel_id)
    validate_channel_descriptor(
        descriptor,
        channel_id,
        context.chain_id,
        context.escrow,
        request.recipient,
        request.currency,
        operator,
    )

    def before_broadcast(prepared: chain.ValidatedOpenTransaction) -> None:
        _check_open_voucher(
            context,
            channel_id=channel_id,
            cumulative=cumulative,
            signature=payload.signature,
            validated=prepared,
            descriptor=descriptor,
            request_amount=request.amount,
        )

    result = await chain.broadcast_open_transaction(
        context.rpc_url,
        serialized_transaction=payload.transaction,
        chain_id=context.chain_id,
        escrow_contract=context.escrow,
        expected_authorized_signer=descriptor.authorized_signer,
        expected_channel_id=channel_id,
        expected_currency=request.currency,
        expected_expiring_nonce_hash=descriptor.expiring_nonce_hash,
        expected_operator=operator,
        expected_payee=request.recipient,
        expected_payer=descriptor.payer,
        fee_payer=context.fee_payer,
        fee_payer_policy=context.fee_payer_policy,
        allowed_fee_tokens=_allowed_fee_tokens(request.currency, context.fee_token),
        challenge_expires=context.challenge.expires,
        before_broadcast=before_broadcast,
        client=context.http_client,
    )
    assert_same_descriptor(result.descriptor, descriptor)
    validate_channel_state(result.state, request.amount)

    def update(current: ChannelState | None) -> ChannelState | None:
        if (
            context.require_voucher_advance
            and current is not None
            and cumulative <= current.highest_voucher_amount
        ):
            raise DeltaTooSmallError("voucher does not add new funds for this request")
        return open_channel_state(
            authorized_signer=authorized_signer(result.descriptor),
            chain_id=context.chain_id,
            channel_id=channel_id,
            current=current,
            descriptor=result.descriptor,
            escrow=context.escrow,
            expiring_nonce_hash=result.expiring_nonce_hash,
            cumulative_amount=cumulative,
            signature=payload.signature,
            state=result.state,
        )

    updated = await context.store.update_channel(channel_id, update)
    if updated is None:
        raise VerificationFailedError("failed to create channel")
    return create_session_receipt(
        challenge_id=context.challenge.id,
        channel_id=channel_id,
        accepted_cumulative=updated.highest_voucher_amount,
        spent=updated.spent,
        units=updated.units,
        tx_hash=result.tx_hash,
    )


async def _handle_top_up(context: CredentialContext, payload: TopUpPayload) -> SessionReceipt:
    request = get_challenge_payment_fields(context.challenge)
    additional = _amount(payload.additional_deposit)
    descriptor = _descriptor(payload)
    channel_id = normalize_channel_id(payload.channel_id)
    validate_channel_descriptor(
        descriptor,
        channel_id,
        context.chain_id,
        context.escrow,
        request.recipient,
        request.currency,
        _expected_operator(context),
    )
    channel = await load_precompile_channel(
        store=context.store,
        channel_id=channel_id,
        descriptor=descriptor,
        chain_id=context.chain_id,
        escrow=context.escrow,
        validate_descriptor=True,
    )
    assert channel.descriptor is not None
    result = await chain.broadcast_top_up_transaction(
        context.rpc_url,
        serialized_transaction=payload.transaction,
        additional_deposit=additional,
        chain_id=context.chain_id,
        descriptor=channel.descriptor,
        escrow_contract=context.escrow,
        expected_channel_id=channel_id,
        expected_currency=request.currency,
        fee_payer=context.fee_payer,
        fee_payer_policy=context.fee_payer_policy,
        allowed_fee_tokens=_allowed_fee_tokens(request.currency, context.fee_token),
        challenge_expires=context.challenge.expires,
        client=context.http_client,
    )
    validate_channel_state(result.state)
    updated = await context.store.update_channel(
        channel_id, lambda current: top_up_channel_state(current=current, state=result.state)
    )
    source = updated or channel
    return create_session_receipt(
        challenge_id=context.challenge.id,
        channel_id=channel_id,
        accepted_cumulative=source.highest_voucher_amount,
        spent=source.spent,
        units=source.units,
        tx_hash=result.tx_hash,
    )


async def _record_pending_close(
    context: CredentialContext, channel_id: str, state: OnChainChannelState
) -> None:
    """Persist a pending close seen on chain and settle while the payee still can."""

    def update(current: ChannelState | None) -> ChannelState | None:
        if current is None:
            return current
        return replace(
            current,
            settled_on_chain=keep_greater(current.settled_on_chain, state.settled),
            close_requested_at=keep_greater(current.close_requested_at, state.close_requested_at),
        )

    closing = await context.store.update_channel(channel_id, update)
    if closing is not None and not closing.finalized and state.deposit > 0:
        await maybe_settle_scheduled(
            channel=closing,
            schedule=ResolvedSettlementSchedule(),
            store=context.store,
            account=context.account,
            rpc_url=context.rpc_url,
            http_client=context.http_client,
            fee_payer=context.fee_payer,
            fee_payer_policy=context.fee_payer_policy,
            fee_token=context.fee_token,
            on_session_settlement=context.on_session_settlement,
            on_session_settlement_failure=context.on_session_settlement_failure,
        )


async def _handle_voucher(context: CredentialContext, payload: VoucherPayload) -> SessionReceipt:
    request = get_challenge_payment_fields(context.challenge)
    channel_id = normalize_channel_id(payload.channel_id)
    voucher = _parse_voucher(payload, channel_id)
    descriptor = _descriptor(payload)
    validate_channel_descriptor(
        descriptor,
        channel_id,
        context.chain_id,
        context.escrow,
        request.recipient,
        request.currency,
        _expected_operator(context),
    )
    # The on-chain read does not depend on the stored channel, so it overlaps the store read;
    # store errors still take precedence.
    started_at = _now_ms()
    reading = asyncio.ensure_future(
        _resolve_voucher_channel_state(context, channel_id, None, force=True)
    )
    try:
        channel = await load_precompile_channel(
            store=context.store,
            channel_id=channel_id,
            descriptor=descriptor,
            chain_id=context.chain_id,
            escrow=context.escrow,
            validate_descriptor=True,
        )
        assert_credential_source_can_spend(
            chain_id=context.chain_id, channel=channel, source=context.credential_source
        )
        if channel.finalized:
            raise ChannelClosedError("channel is finalized")
    except BaseException:
        reading.cancel()
        with contextlib.suppress(BaseException):
            await reading
        raise
    state = await reading
    reconciled = channel
    if channel.close_requested_at != 0:
        now = int(time.time())
        reconciled = (
            await context.store.update_channel(
                channel_id,
                lambda current: reconcile_expired_pending_close(
                    current=current, now=now, state=state
                ),
            )
            or channel
        )
    if state.close_requested_at != 0:
        await _record_pending_close(context, channel_id, state)
        raise ChannelClosedError("channel has a pending close request")
    return await verify_and_accept_voucher(
        store=context.store,
        challenge_id=context.challenge.id,
        channel=reconciled,
        voucher=voucher,
        channel_state=state,
        chain_id=context.chain_id,
        escrow=context.escrow,
        min_voucher_delta=context.min_voucher_delta,
        require_advance=context.require_voucher_advance,
        verified_at=started_at,
    )


_SEND_METHODS = frozenset(
    {"eth_sendRawTransaction", "eth_sendRawTransactionSync", "eth_sendTransaction"}
)


class _SendTracker:
    """An RPC client wrapper recording whether a transaction was handed to the node."""

    def __init__(self, client: httpx.AsyncClient | None) -> None:
        self._client = client
        self.attempted = False

    async def post(self, url: str, *, json: Any = None, **kwargs: Any) -> httpx.Response:
        import httpx

        content: object = json
        method = cast(dict[str, Any], content).get("method") if isinstance(content, dict) else None
        if method in _SEND_METHODS:
            self.attempted = True
        if self._client is not None:
            return await self._client.post(url, json=cast(Any, content), **kwargs)
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            return await client.post(url, json=cast(Any, content), **kwargs)


async def _handle_close(context: CredentialContext, payload: ClosePayload) -> SessionReceipt:
    channel, state, cumulative, capture, channel_id = await _check_close(context, payload)
    assert channel.descriptor is not None
    descriptor = channel.descriptor
    now = int(time.time()) or 1
    pending_close_started_at = now
    marked = False

    def mark(current: ChannelState | None) -> ChannelState | None:
        nonlocal capture, marked
        update = mark_pending_close(
            close_requested_at=pending_close_started_at,
            cumulative_amount=cumulative,
            current=reconcile_expired_pending_close(current=current, now=now, state=state),
            on_chain_deposit=state.deposit,
            on_chain_settled=state.settled,
        )
        if update.state is not None:
            capture = update.capture_amount
            marked = True
        return update.state

    await context.store.update_channel(channel_id, mark)
    # Pin the close transaction's expiry to the marker so an expired marker proves it can
    # no longer land.
    valid_before = now + PENDING_CLOSE_VALIDITY_SECONDS
    tracker = _SendTracker(context.http_client)
    tracked_client = cast("httpx.AsyncClient", tracker)
    try:
        assert_settlement_sender(
            operation="close",
            channel_id=channel_id,
            operator=channel.operator or ZERO_ADDRESS,
            payee=channel.payee,
            sender=context.account.address if context.account is not None else None,
        )
        assert context.account is not None
        tx_hash = await chain.close_on_chain(
            context.rpc_url,
            context.account,
            descriptor,
            cumulative,
            capture,
            payload.signature,
            escrow=context.escrow,
            fee_payer=context.fee_payer,
            fee_payer_policy=context.fee_payer_policy,
            fee_token=context.fee_token,
            candidate_fee_tokens=[channel.token],
            valid_before=valid_before,
            client=tracked_client,
        )
        receipt = await chain.wait_for_successful_receipt(
            context.rpc_url, tx_hash, client=context.http_client
        )
    except Exception as error:
        await report_session_settlement_failure(
            context.on_session_settlement_failure,
            SessionSettlementFailureContext(
                chain_id=context.chain_id, channel_id=channel_id, error=error, trigger="close"
            ),
        )
        # A close whose send was attempted may still land, so it keeps the marker until it
        # expires and a later credential reconciles it. Verification errors prove a revert.
        failed = not tracker.attempted or isinstance(error, VerificationFailedError)
        if marked and failed:

            def clear(current: ChannelState | None) -> ChannelState | None:
                if current is not None and current.close_requested_at == pending_close_started_at:
                    return replace(current, close_requested_at=0)
                return current

            await context.store.update_channel(channel_id, clear)
        raise
    closed = chain.get_channel_event(receipt, "ChannelClosed", channel_id)
    settled_to_payee = int(closed["settledToPayee"])
    refunded_to_payer = int(closed["refundedToPayer"])
    if settled_to_payee > capture or settled_to_payee + refunded_to_payer > state.deposit:
        raise VerificationFailedError("ChannelClosed amounts do not match state")
    final_capture = capture
    updated = await context.store.update_channel(
        channel_id,
        lambda current: finalize_closed_channel_state(
            capture_amount=final_capture,
            channel_id=channel_id,
            cumulative_amount=cumulative,
            current=current,
            signature=payload.signature,
        ),
    )
    await emit_session_settlement(
        context.on_session_settlement,
        SessionSettlementContext(
            tx_hash=tx_hash,
            channel_id=channel_id,
            trigger="close",
            amount=settled_to_payee,
            delta=settled_to_payee - state.settled,
        ),
    )
    source = updated or channel
    return create_session_receipt(
        challenge_id=context.challenge.id,
        channel_id=channel_id,
        accepted_cumulative=cumulative,
        spent=source.spent,
        units=source.units,
        tx_hash=tx_hash,
    )
