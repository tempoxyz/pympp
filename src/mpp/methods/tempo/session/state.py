"""Pure policy and lifecycle transitions for Tempo sessions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .models import MAX_UINT96, SessionPolicy, SessionStatus


class SessionEvent(StrEnum):
    """Events accepted by the durable lifecycle reducer."""

    OPEN_PREPARED = "openPrepared"
    OPEN_ACCEPTED = "openAccepted"
    TOP_UP_PREPARED = "topUpPrepared"
    TOP_UP_ACCEPTED = "topUpAccepted"
    VOUCHER_PREPARED = "voucherPrepared"
    VOUCHER_ACCEPTED = "voucherAccepted"
    CLOSE_PREPARED = "closePrepared"
    CLOSE_ACCEPTED = "closeAccepted"


_TRANSITIONS: dict[tuple[SessionStatus | None, SessionEvent], SessionStatus] = {
    (None, SessionEvent.OPEN_PREPARED): SessionStatus.OPENING,
    (SessionStatus.OPENING, SessionEvent.OPEN_ACCEPTED): SessionStatus.ACTIVE,
    (SessionStatus.ACTIVE, SessionEvent.TOP_UP_PREPARED): SessionStatus.TOPPING_UP,
    (SessionStatus.TOPPING_UP, SessionEvent.TOP_UP_ACCEPTED): SessionStatus.ACTIVE,
    (SessionStatus.ACTIVE, SessionEvent.VOUCHER_PREPARED): SessionStatus.VOUCHER_PENDING,
    (SessionStatus.VOUCHER_PENDING, SessionEvent.VOUCHER_ACCEPTED): SessionStatus.ACTIVE,
    (SessionStatus.ACTIVE, SessionEvent.CLOSE_PREPARED): SessionStatus.CLOSING,
    (SessionStatus.CLOSING, SessionEvent.CLOSE_ACCEPTED): SessionStatus.CLOSED,
}


def transition(status: SessionStatus | None, event: SessionEvent) -> SessionStatus:
    """Apply a lifecycle event or reject an invalid transition."""

    try:
        return _TRANSITIONS[(status, event)]
    except KeyError as error:
        current = "idle" if status is None else status.value
        raise ValueError(f"invalid Tempo session transition: {current} -> {event.value}") from error


def assert_uint96(value: int, field: str) -> int:
    """Return an amount after validating the TIP-1034 uint96 boundary."""

    if value < 0 or value > MAX_UINT96:
        raise ValueError(f"{field} is outside uint96 bounds")
    return value


def resolve_opening_deposit(
    *,
    request_amount: int,
    suggested_deposit: int | None,
    policy: SessionPolicy,
) -> int:
    """Choose the bounded opening deposit, following mppx's policy order."""

    assert_uint96(request_amount, "request amount")
    if request_amount > policy.max_cumulative_spend:
        raise ValueError("request amount exceeds max cumulative spend")
    if request_amount > policy.max_deposit:
        raise ValueError("request amount exceeds max deposit")
    if policy.opening_deposit is not None:
        if policy.opening_deposit < request_amount:
            raise ValueError("opening deposit is below request amount")
        if policy.opening_deposit > policy.max_deposit:
            raise ValueError("opening deposit exceeds max deposit")
        return policy.opening_deposit
    proposed = max(request_amount, suggested_deposit or 0)
    deposit = min(proposed, policy.max_deposit)
    if deposit == 0:
        raise ValueError("opening deposit must be positive")
    return deposit


def resolve_top_up(
    *,
    deposit: int,
    required_cumulative: int,
    suggested_deposit: int | None,
    policy: SessionPolicy,
) -> int:
    """Choose a bounded refill amount or zero when current deposit is enough."""

    assert_uint96(deposit, "deposit")
    assert_uint96(required_cumulative, "required cumulative")
    if required_cumulative <= deposit:
        return 0
    if required_cumulative > policy.max_cumulative_spend:
        raise ValueError("required cumulative exceeds max cumulative spend")
    if required_cumulative > policy.max_deposit:
        raise ValueError("required cumulative exceeds max deposit")

    shortfall = required_cumulative - deposit
    preferred = policy.top_up_amount
    if preferred is None and suggested_deposit is not None:
        preferred = max(0, suggested_deposit - deposit)
    additional = max(shortfall, preferred or shortfall)
    additional = min(additional, policy.max_top_up, policy.max_deposit - deposit)
    if additional < shortfall:
        raise ValueError("top-up policy cannot cover the required cumulative amount")
    return additional


@dataclass(frozen=True, slots=True)
class VoucherPlan:
    """Next monotonic cumulative authorization and whether a top-up is needed."""

    cumulative: int
    top_up: int


def resolve_voucher_plan(
    *,
    authorized_cumulative: int,
    accepted_cumulative: int,
    spent: int,
    request_amount: int,
    required_cumulative: int | None,
    deposit: int,
    suggested_deposit: int | None,
    policy: SessionPolicy,
    min_voucher_delta: int = 0,
) -> VoucherPlan:
    """Resolve a monotonic voucher boundary and any prerequisite deposit."""

    baseline = max(authorized_cumulative, accepted_cumulative, spent)
    required = max(
        baseline + request_amount,
        required_cumulative or 0,
    )
    assert_uint96(min_voucher_delta, "minimum voucher delta")
    if required > accepted_cumulative and required - accepted_cumulative < min_voucher_delta:
        required = accepted_cumulative + min_voucher_delta
    assert_uint96(required, "voucher cumulative")
    if required > policy.max_cumulative_spend:
        raise ValueError("voucher cumulative exceeds max cumulative spend")
    return VoucherPlan(
        cumulative=required,
        top_up=resolve_top_up(
            deposit=deposit,
            required_cumulative=required,
            suggested_deposit=suggested_deposit,
            policy=policy,
        ),
    )
