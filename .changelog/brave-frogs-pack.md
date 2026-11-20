---
pympp: patch
---

Fixed session credential source binding to use the channel's funding payer instead of the signing account, ensuring delegated voucher signers still identify the funding account. Updated server-side verification to only accept the channel payer as a valid credential source, with voucher signing authority checked separately.
