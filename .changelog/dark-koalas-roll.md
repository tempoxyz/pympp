---
pympp: minor
---

Added `mpp.extensions.identity.erc8004`, a new identity provider for ERC-8004 agents that sign requests with their registered wallet (EOA or ERC-1271). Includes a client prover (`erc8004.client.prover`) and a server verifier/payment check (`erc8004.server.create`), along with `Agent`, `AgentRef`, and related helpers. Added `agent-id` and `agent-signature` to `mpp.identity.REQUEST_HEADERS`.
