---
pympp: patch
---

Bound a session credential's source to the channel's funding payer rather than the voucher signer, so a delegated voucher signer still names the funding account; the server accepts only the channel payer as the source and checks voucher signing authority separately (mppx#1326).
