# Tempo sessions with HTTPX

`pympp` keeps TIP-1034 channel state and every pending signed operation in a
session store. The pending operation is written before HTTP submission, so a
timeout or restart reuses the exact transaction or voucher instead of creating
a second deposit or a higher voucher.

```python
import httpx

from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo.session import (
    AsyncSessionPaymentTransport,
    SQLiteSessionStore,
    SessionPolicy,
    TempoAccountCredentialProvider,
    TempoSessionManager,
    TempoSessionRpc,
)

account = TempoAccount.from_env("TEMPO_PRIVATE_KEY")
rpc = TempoSessionRpc("https://rpc.moderato.tempo.xyz")
store = SQLiteSessionStore("tempo-sessions.sqlite3")
manager = TempoSessionManager(
    provider=TempoAccountCredentialProvider(account),
    store=store,
    rpc=rpc,
    chain_id=42431,
    policy=SessionPolicy(
        max_deposit=10_000_000,
        max_top_up=5_000_000,
        max_cumulative_spend=10_000_000,
    ),
)
transport = AsyncSessionPaymentTransport(manager)

async with httpx.AsyncClient(transport=transport) as client:
    response = await client.get("https://service.example/session")
    response.raise_for_status()

    # Application SSE frames remain in the response while payment control
    # frames are handled automatically.
    async for line in response.aiter_lines():
        print(line)

channel_id = (await manager.list_sessions())[0].channel_id
await transport.close_session(channel_id, "https://service.example/session")
store.close()
```

All policy amounts are integer base units. Use `SessionPaymentTransport` with
`httpx.Client` for the equivalent synchronous flow, or attach the same manager
to `tempo(..., session_manager=manager)` when using pympp's standard async
`PaymentTransport`.

The credential provider is an interface: the included implementation wraps the
existing private-key `TempoAccount`, while a managed wallet can implement the
same transaction- and digest-signing methods later. HTTP and SSE are supported;
WebSocket session driving is intentionally deferred in this first implementation.
