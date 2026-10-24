---
pympp: patch
---

Fixed canonicalization of secp256k1 recovery IDs in Tempo transactions before broadcast, ensuring replay keys and receipt hashes match the node's derived values. Added `_canonical_signature` and `_canonical_raw_transaction` helpers to normalize raw (0/1) recovery IDs to the 27/28 encoding accepted by Tempo nodes.
