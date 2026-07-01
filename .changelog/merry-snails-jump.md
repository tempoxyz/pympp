---
pympp: patch
---

Fixed rejection of ABI-encoded calldata with trailing padding bytes in Tempo transfer, approve, and swap calls. Added exact-length validation constants and updated `_match_single_transfer_calldata`, `_match_transfer_calldata`, and `_validate_call_scope` to reject any calldata that does not match the expected byte length precisely.
