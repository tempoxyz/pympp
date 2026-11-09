---
pympp: patch
---

Fixed sponsorship slot tracking to reserve daily capacity before the signed simulation is sent to the RPC, since a signed simulation can be reconstructed and broadcast outside the client. Replaced the `_SendTracker` wrapping approach with a dedicated `before_sponsor_exposure` callback parameter on `send_credential_transaction` and `broadcast_top_up_transaction`.
