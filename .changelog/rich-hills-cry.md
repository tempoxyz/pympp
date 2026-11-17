---
pympp: patch
---

Fixed the MCP client and HTTP transport to pay a new challenge offered after a rejected credential (e.g., the real charge after a zero-amount Tempo proof is refused for insufficient credit). Refactored `McpClient` payment logic into `_pay` and `_select_challenge` methods, added a `_may_pay_again` guard to prevent re-paying already-broadcast or spendable credentials, and bounded new challenge rounds by the existing retry limit.
