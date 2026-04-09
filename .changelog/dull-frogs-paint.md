---
pympp: patch
---

Cached Tempo chain IDs per RPC URL to avoid redundant `eth_chainId` calls. Also parallelized `eth_getTransactionCount` and `eth_gasPrice` fetches using `asyncio.gather`.
