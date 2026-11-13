---
pympp: patch
---

Fixed edge cases in Tempo ID token verification: a DPoP proof whose ID has a lone surrogate is rejected as malformed instead of as a replay store outage, only a failing replay store rejects as unavailable, the key set records a failed refetch even when it serves the stale set so the 30-second retry limit holds, and a remembered key set error no longer accumulates tracebacks.
