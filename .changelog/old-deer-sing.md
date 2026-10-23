---
pympp: patch
---

Reverted dict body digest to preserve JSON key insertion order instead of sorting keys, aligning behaviour with mppx's `JSON.stringify`. Updated tests to reflect and verify the new insertion-order semantics.
