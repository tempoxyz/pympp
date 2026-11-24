---
pympp: patch
---

Fixed Tempo charge verification to align with the spec: access key checks now validate that the returned key ID is non-zero and matches the signer, split amounts are serialized as base-10 integer strings without leading zeros, and broadcast marker handling was refactored to correctly track and reconcile unsponsored pull transactions across retries. A Challenge that expires during the last pre-broadcast lookups is no longer broadcast, and a sponsored pull keeps its broadcast marker after a JSON-RPC error that leaves the outcome open, so a retry settles the transaction once it mines.
