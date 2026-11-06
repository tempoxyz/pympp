---
pympp: minor
---

Added an `origin` parameter to `session()`, `SessionMethod.__init__`, and `SessionMethod.create_session_credential` to explicitly pin the HTTP origin for credential creation and channel recovery. Extended realm boundary enforcement to cover Tempo session payments in addition to zero-amount Tempo charges, fixing a relay attack vector in both `PaymentTransport` and `McpClient`. Fixed `SessionManager` to forward `trusted_tempo_realms` to its internal `PaymentTransport`.

Clients now refuse a Tempo session Challenge whose realm isn't the request host, and no longer reuse or adopt stored channels without a matching origin, as mppx does. Servers that use a realm other than their hostname (for example the `FLY_APP_NAME` or `HEROKU_APP_NAME` default) should set `realm` to their host, or clients pin it with `trusted_tempo_realms`. Open channels stored before this release have no origin and raise "Session channel origin mismatch": close or delete them, or use a separate channel store per origin.
