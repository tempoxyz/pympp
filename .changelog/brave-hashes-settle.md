---
pympp: minor
---

Mapped server verification errors to payment errors. `VerificationError` now subclasses `VerificationFailedError`, so invalid credentials return a 402 with a fresh challenge instead of escaping as an unhandled exception. Added `CredentialReplayedError`, a `VerificationError` subclass with the same status and problem type, for replayed Tempo transaction hashes. Added `InternalPaymentError` (status 500) for RPC, fee payer and configuration failures, missing receipts, and any non-cancellation failure after a Tempo transaction is broadcast. Its message is generic and the original exception is kept only as `__cause__`. Servers and the MCP transport re-raise it without a retry challenge, so clients are not asked to pay again for a payment that may have landed.
