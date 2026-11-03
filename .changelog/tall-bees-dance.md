---
pympp: patch
---

Fixed receipt recovery after Tempo `ExpiringNonceReplay` broadcast errors by extending the already-known transaction regex to match this error pattern. Added tests covering both JSON-RPC response and exception forms of the error.
