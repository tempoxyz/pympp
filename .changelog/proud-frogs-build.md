---
pympp: patch
---

Fixed authentication parameter parsing to use a bounded cursor instead of `finditer`, rejecting malformed inputs (invalid separators, trailing commas, unrecognised tokens) and oversized payloads before they can block async clients.
