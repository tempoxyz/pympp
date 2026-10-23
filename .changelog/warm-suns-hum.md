---
pympp: patch
---

Fixed external fee payer sponsor token validation to respect the configured `allowed_fee_tokens` allowlist. Added `_transaction_fee_token` helper to extract the fee token from a signed Tempo transaction and updated `ChargeIntent` to reject sponsored transactions whose fee token is not in the configured allowlist.
