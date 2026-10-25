---
pympp: patch
---

Fixed split memos using the MPP attribution format are now rejected before challenge issuance or client payment, preventing a fixed split leg from being used to authorize unintended charges. Removed the `fixed` exemption from MPP memo binding checks so all matched transfer logs carrying an MPP attribution memo must be bound to the current challenge and realm. Added validation in both the server's `transform_request` and the client's `create_credential` path, with updated tests reflecting the stricter behavior.
