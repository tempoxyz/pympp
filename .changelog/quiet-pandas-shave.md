---
pympp: patch
---

`BodyDigest.verify` now accepts digests in the RFC 9530 Byte Sequence form (`sha-256=:<base64>:`) that the MPP spec uses, in addition to the bare `sha-256=<base64>` form.
