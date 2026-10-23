---
pympp: patch
---

Fixed Tempo charge verification to perform a single receipt lookup after definitive broadcast RPC errors, since the node may have included the transaction before its reply failed. Extracted shared receipt verification logic into `_verify_recovered_receipt` and added `_lookup_broadcast_receipt` for the non-ambiguous error path.
