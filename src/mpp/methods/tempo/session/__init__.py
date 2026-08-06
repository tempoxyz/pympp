"""Client support for Tempo TIP-1034 payment sessions."""

from .credentials import SessionCredentialProvider, TempoAccountCredentialProvider
from .manager import (
    SessionRecoveryRequiredError,
    TempoSessionManager,
    is_tip1034_session_challenge,
    resolve_challenge,
)
from .models import (
    TIP20_CHANNEL_RESERVE,
    ChannelDescriptor,
    PendingOperation,
    PendingStatus,
    SessionAction,
    SessionPolicy,
    SessionReceipt,
    SessionRecord,
    SessionSnapshot,
    SessionStatus,
)
from .protocol import (
    ChannelState,
    TempoSessionProtocol,
    TempoSessionRpc,
    channel_scope,
    compute_channel_id,
    compute_expiring_nonce_hash,
    decode_session_receipt,
    decode_session_snapshot,
    verify_voucher_signature,
    voucher_digest,
)
from .sse import NeedVoucherEvent, SseFrame, SseParser
from .state import (
    SessionEvent,
    VoucherPlan,
    resolve_opening_deposit,
    resolve_top_up,
    resolve_voucher_plan,
    transition,
)
from .store import MemorySessionStore, SessionStore, SQLiteSessionStore
from .transport import AsyncSessionPaymentTransport, SessionPaymentTransport
