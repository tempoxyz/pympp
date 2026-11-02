---
pympp: patch
---

Fixed a bug where opaque string reuse incorrectly compared decoded values using Python's `True == 1` / `False == 0` equality, causing bool/int mismatches to be treated as unchanged. Canonical base64url encodings are now compared instead of decoded values.
