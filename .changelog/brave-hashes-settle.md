---
pympp: minor
---

Mapped server verification errors to payment errors. `VerificationError` now subclasses `VerificationFailedError`, so invalid credentials (including replayed transaction hashes, raised as the new `TransactionHashUsedError`) return a 402 with a fresh challenge instead of escaping as an unhandled exception. Added `InternalPaymentError` (status 500) for RPC, fee payer, and configuration failures, missing receipts, and any failure after a Tempo transaction is broadcast; servers and the MCP transport re-raise it without a retry challenge so clients are not asked to pay again for a payment that may have landed. Rewrapped errors, including Tempo receipt lookup failures, now chain the original exception.
