---
pympp: minor
---

Added funding currency detection for hash-based charge receipts by fetching the transaction via `eth_getTransactionByHash` and inspecting its call data. Introduced `_rpc_transaction_calls` and `_calls_funding_currency` helpers to normalize and classify payment routes (direct transfer or token swap), and refactored `_validate_hash` into `_validate_hash_and_sender` to also return the expected sender for the lookup.
