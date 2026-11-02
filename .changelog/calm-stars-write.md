---
pympp: patch
---

Fixed `BodyDigest.verify` to accept RFC 9530 byte-sequence digest format (`sha-256=:<base64>:`) in addition to the existing plain format, and added tests covering both valid and malformed byte-sequence inputs.
