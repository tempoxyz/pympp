---
pympp: patch
---

Fixed the issuer's opaque string being re-encoded canonically when echoed back in credentials. The challenge now preserves and echoes the issuer's original opaque encoding unchanged, as required by the protocol (clients MUST NOT modify opaque).
