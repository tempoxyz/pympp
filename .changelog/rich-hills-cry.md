---
pympp: patch
---

Fixed `McpClient` to pay a new Challenge offered after a refused Credential, such as the real charge after a zero-amount Tempo proof is refused for insufficient credit. `McpClient` also resent the same Credential, rather than signing another, when the same Challenge was offered again.
