"""TIP-1034 session server: channel store, verification, settlement and close supervision.

Mirrors mppx ``tempo/session/server``. :func:`session` is the server method (also exported as
``mpp.methods.tempo.server.session``); :func:`charge`, :func:`credit`, :func:`settle`,
:func:`settle_batch` and :func:`supervise_closes` manage channels outside a route.
"""

from typing import TYPE_CHECKING, Any

from mpp._lazy_exports import load_lazy_attr

if TYPE_CHECKING:
    from mpp.methods.tempo.session.server.close_supervisor import (
        CloseSupervision,
        CloseSupervisionOutcome,
        supervise_closes,
    )
    from mpp.methods.tempo.session.server.schedule import (
        ResolvedSettlementSchedule,
        SettlementSchedule,
        resolve_settlement_schedule,
    )
    from mpp.methods.tempo.session.server.session import (
        SessionPaymentReceipt,
        charge,
        credit,
        session,
    )
    from mpp.methods.tempo.session.server.settlement import (
        OnSessionSettlement,
        OnSessionSettlementFailure,
        SessionSettlementContext,
        SessionSettlementFailureContext,
        settle,
        settle_batch,
    )
    from mpp.methods.tempo.session.server.store import (
        ChannelState,
        CreditResult,
        IdempotencyKeyConflictError,
        resolve_settleable_voucher,
    )

_EXTRA_INSTALL_HINT = 'Install the "tempo" extra to use this module: pip install "pympp[tempo]"'

_LAZY_EXPORTS = {
    "mpp.methods.tempo.session.server.session": (
        "SessionPaymentReceipt",
        "charge",
        "credit",
        "session",
    ),
    "mpp.methods.tempo.session.server.settlement": (
        "OnSessionSettlement",
        "OnSessionSettlementFailure",
        "SessionSettlementContext",
        "SessionSettlementFailureContext",
        "settle",
        "settle_batch",
    ),
    "mpp.methods.tempo.session.server.close_supervisor": (
        "CloseSupervision",
        "CloseSupervisionOutcome",
        "supervise_closes",
    ),
    "mpp.methods.tempo.session.server.schedule": (
        "ResolvedSettlementSchedule",
        "SettlementSchedule",
        "resolve_settlement_schedule",
    ),
    "mpp.methods.tempo.session.server.store": (
        "ChannelState",
        "CreditResult",
        "IdempotencyKeyConflictError",
        "resolve_settleable_voucher",
    ),
}


def __getattr__(name: str) -> Any:
    return load_lazy_attr(__name__, name, _LAZY_EXPORTS, globals(), _EXTRA_INSTALL_HINT)


__all__ = [
    "ChannelState",
    "CloseSupervision",
    "CloseSupervisionOutcome",
    "CreditResult",
    "IdempotencyKeyConflictError",
    "OnSessionSettlement",
    "OnSessionSettlementFailure",
    "ResolvedSettlementSchedule",
    "SessionPaymentReceipt",
    "SessionSettlementContext",
    "SessionSettlementFailureContext",
    "SettlementSchedule",
    "charge",
    "credit",
    "resolve_settleable_voucher",
    "resolve_settlement_schedule",
    "session",
    "settle",
    "settle_batch",
    "supervise_closes",
]
