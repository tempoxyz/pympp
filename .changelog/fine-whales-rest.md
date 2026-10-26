---
pympp: minor
---

Added `JsonRpcAccount` and `WalletRequest` to the public API, enabling Tempo charges to be paid with a wallet that signs over JSON-RPC. The new account type prefers EIP-5792 push mode (`wallet_sendCalls`) with an optional fallback to `eth_sendTransaction`, and signs pull-only challenges via `eth_signTransaction`. The `tempo.charge()` helper now also accepts a plain address string as the `account` argument.
