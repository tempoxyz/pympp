"""TIP-1034 session client (mppx src/tempo/session/client).

``session(...)`` is the client method for :class:`mpp.client.Mpp`;
``session_manager(...)`` drives one channel with fetch, top-up and close.
"""

from mpp.methods.tempo.session.client._manager import (
    PaymentResponse,
    SessionManager,
    session_manager,
)
from mpp.methods.tempo.session.client._session import SessionMethod, session
from mpp.methods.tempo.session.client._store import (
    ChannelEntry,
    ChannelStore,
    JsonChannelStore,
    MemoryChannelStore,
    UncertainFundingError,
    create_channel_store,
    create_json_channel_store,
)

__all__ = [
    "ChannelEntry",
    "ChannelStore",
    "JsonChannelStore",
    "MemoryChannelStore",
    "PaymentResponse",
    "SessionManager",
    "SessionMethod",
    "UncertainFundingError",
    "create_channel_store",
    "create_json_channel_store",
    "session",
    "session_manager",
]
