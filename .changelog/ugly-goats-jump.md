---
pympp: minor
---

Added `rpc_url_for_chain` as a new public function in `mpp.methods.tempo`. Added an optional `http_request` parameter to `Mpp.validate_credential` and `Mpp.broadcast_credential` to enforce route scope binding, and enriched `ChargeIntent` settlement details with `payer_verified`, `transaction_hash`, and `valid_before` fields.
