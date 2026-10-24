---
pympp: patch
---

Fixed validation in `_encode_transfer_with_memo` to reject non-hex characters in memo values, preventing invalid calldata from being generated for `transferWithMemo` calls.
