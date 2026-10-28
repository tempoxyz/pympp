"""TIP-1034 session client (mppx src/tempo/session/client).

``session(...)`` is the client method for :class:`mpp.client.Mpp`;
``session_manager(...)`` drives one channel with fetch, top-up and close.
"""

from mpp.methods.tempo.session.client.manager import (
    PaymentResponse,
    SessionManager,
    session_manager,
)
from mpp.methods.tempo.session.client.session import SessionMethod, session
from mpp.methods.tempo.session.client.state import (
    SessionContext,
    plan_credential,
    resolve_automatic_top_up,
    resolve_opening_deposit,
)
from mpp.methods.tempo.session.client.store import (
    ChannelEntry,
    ChannelStore,
    JsonChannelStore,
    MemoryChannelStore,
    UncertainFundingError,
    channel_key,
    create_channel_store,
    create_json_channel_store,
    deserialize_entry,
    serialize_entry,
)

__all__ = [
    "ChannelEntry",
    "ChannelStore",
    "JsonChannelStore",
    "MemoryChannelStore",
    "PaymentResponse",
    "SessionContext",
    "SessionManager",
    "SessionMethod",
    "UncertainFundingError",
    "channel_key",
    "create_channel_store",
    "create_json_channel_store",
    "deserialize_entry",
    "plan_credential",
    "resolve_automatic_top_up",
    "resolve_opening_deposit",
    "serialize_entry",
    "session",
    "session_manager",
]
