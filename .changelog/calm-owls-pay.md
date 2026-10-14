---
pympp: minor
---

Exposed the verified payer as `payer` on `Validation` and on server-side `Receipt`s returned by verification (route handlers, `verify_or_challenge`, `Mpp.broadcast_credential`, and payment success events); it is never serialized into the `Payment-Receipt` header. Tempo charges report the transaction sender for pull-mode credentials and the sender of the matched transfers for hash credentials. Tempo pull-mode credentials that carry a source are now rejected unless the source is on the charge chain and names the transaction sender, fee payer envelopes must be signed by their declared sender, and fee payer co-signing may not change the sender. Added public `parse_pkh_source` and `PkhSource` to `mpp.methods.tempo`.
