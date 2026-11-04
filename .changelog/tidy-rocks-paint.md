---
pympp: minor
---

Added an `origin` parameter to `session()`, `SessionMethod.__init__`, and `SessionMethod.create_session_credential` to explicitly pin the HTTP origin for credential creation and channel recovery. Extended realm boundary enforcement to cover Tempo session payments in addition to zero-amount Tempo charges, fixing a relay attack vector in both `PaymentTransport` and `McpClient`. Fixed `SessionManager` to forward `trusted_tempo_realms` to its internal `PaymentTransport`.
