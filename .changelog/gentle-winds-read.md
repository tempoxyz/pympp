---
pympp: patch
---

Fixed oversized `Authorization` header values being rejected before the `payment.failed` event could be emitted. Added early size check in `verify_or_challenge` that now routes oversized headers through the `fail` path, ensuring `payment.failed` hooks are triggered with a `MalformedCredentialError`.
