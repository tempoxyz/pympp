---
pympp: major
---

Added `check_secret_key()` and `MIN_SECRET_KEY_BYTES = 32` to the public API, and enforced a minimum 32-byte HMAC secret at both `Mpp` construction and challenge ID generation, raising `ValueError` for shorter secrets. Updated all tests, examples, and CI fixtures to use secrets of at least 32 bytes and refreshed golden test vectors accordingly.
