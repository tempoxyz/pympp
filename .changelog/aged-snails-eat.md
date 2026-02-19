---
pympp: minor
---

Added extensive test coverage for memo-based transfers, including unit tests for `_match_transfer_calldata` and `_verify_transfer_logs` with memo fields, integration tests for end-to-end charge flows with server-specified memos, and new test modules for body digest computation, error types, expires helpers, and keychain signature handling.
