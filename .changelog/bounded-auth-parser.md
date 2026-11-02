---
pympp: patch
---

Bounded `WWW-Authenticate` and authentication-parameter parsing at 64 KiB, so oversized challenges are rejected before they are scanned.
