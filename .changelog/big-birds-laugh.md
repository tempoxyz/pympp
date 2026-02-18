---
pympp: minor
---

Added fee payer sponsorship support to the Tempo payment method. Servers can now configure a local `TempoAccount` as a fee payer to co-sign client transactions directly, with automatic fallback to an external fee payer service when no local account is configured. Added `fee_payer` parameter to `tempo()`, `ChargeIntent`, and `Mpp.pay()`/`Mpp.charge()`, along with comprehensive tests covering local co-signing, external fallback, and priority logic.
