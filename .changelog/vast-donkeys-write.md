---
pympp: patch
---

Fixed a bug where a sponsored challenge that expired during RPC round-trip preparation could still be signed by rechecking the validity floor immediately before transaction signing.
