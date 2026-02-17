# Changelog

## 0.1.1 (2026-02-17)

### Patch Changes

- Test publish to verify end-to-end PyPI release pipeline. (by @BrendanRyan, [#44](https://github.com/tempoxyz/pympp/pull/44))

## 0.1.0 (2026-02-17)

### Minor Changes

- Added HMAC-bound challenge IDs for stateless MCP transport security and support for optional description/externalId fields in ChargeRequest. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Renamed `@requires_payment` decorator to `@pay` across the codebase, including all documentation, examples, and tests. Added `server.pay()` decorator method on `Mpp` class. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Removed streaming payment support from the Tempo payment method. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))

### Patch Changes

- Switched pytempo dependency from git reference to PyPI package version. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Fixed conformance issues by rejecting duplicate authentication parameters and requiring the `method` field in payment receipts. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Added `sort_keys=True` to all `json.dumps()` calls to ensure JCS (RFC 8785) canonical JSON serialization when generating challenge IDs and credentials. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))
- Switched payment token from AlphaUSD to PathUSD by updating currency address from `0x20c0000000000000000000000000000000000001` to `0x20c0000000000000000000000000000000000000` and removed deprecated `ALPHA_USD` constant. (by @BrendanRyan, [#41](https://github.com/tempoxyz/pympp/pull/41))

## `pympp@0.0.1`

### Patch Changes

**Breaking:** `tempo()` now requires an explicit `intents` parameter. The implicit `ChargeIntent` default has been removed. (by @BrendanRyan, [#26](https://github.com/tempoxyz/pympp/pull/26))
- Initial release of pympp - HTTP 402 Payment Authentication for Python. (by @BrendanRyan, [#26](https://github.com/tempoxyz/pympp/pull/26))

