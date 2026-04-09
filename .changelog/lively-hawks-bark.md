---
pympp: patch
---

Replaced `eth_sendRawTransaction` + polling loop with `eth_sendRawTransactionSync` in Tempo's verify flow, eliminating the separate receipt polling step and extracting the transaction hash directly from the receipt response.
