---
pympp: patch
---

Fixed companion Transfer and TransferWithMemo events (emitted by TIP-20 for a single token movement) being counted as two separate transfers in split payment verification. Paired events are now deduplicated by token, sender, recipient, and amount before log matching, ensuring routed payments and multi-split receipts are validated correctly.
