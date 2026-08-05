---
pympp: minor
---

Added split credential validation and broadcast APIs (`validate_credential`, `broadcast_credential`) alongside a new `SplitIntent` protocol to separate advisory and terminal charge phases. Introduced a `Relay` class that delegates Tempo charge validation and finalization to the Tempo API relay, and added a `charge-relay` example demonstrating FastAPI route protection settled through the relay.
