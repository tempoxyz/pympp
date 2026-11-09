---
pympp: patch
---

Added resumption of stalled Zone withdrawals when a fresh Challenge is issued for the same request, preventing a second withdrawal from being sent. Introduced `_zone_request_key` and `_stalled_zone_withdrawal` helpers to identify and reuse an in-flight withdrawal across Challenge reissuances.
