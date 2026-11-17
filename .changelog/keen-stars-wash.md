---
pympp: minor
---

Added `assert_credential_source_is_payer` to bind an opening credential's source to the transaction payer, verifying identity via direct signature, inline key authorization, or an on-chain access key. Updated `_check_open_voucher` and related internal callsites to use the new async verification flow.
