---
pympp: patch
---

Fixed client chain policy enforcement to reject challenges that attempt to switch the client to a different chain. Clients pinned to a chain (via `chain_id` or `rpc_url`) now raise a `ValueError` immediately instead of silently following the challenge's `chainId`.
