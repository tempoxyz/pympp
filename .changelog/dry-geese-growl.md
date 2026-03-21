---
pympp: minor
---

Added access key signing support for Tempo transactions. When `root_account` is set, nonce and gas estimation now use the root account (smart wallet) address, transactions are signed via `sign_tx_access_key`, and the credential source reflects the root account rather than the access key address.
