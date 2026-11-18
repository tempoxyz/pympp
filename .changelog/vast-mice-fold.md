---
pympp: minor
---

Added TIP-1166 configurable account voucher signers: `voucher_signer=ConfigurableAccount(...)` on the session client and `configurable_vouchers=True` on the server `session()` (off by default), with `SignerConfigChangedError` and `ConfigurableVouchersUnsupportedError`. Servers now record each channel's opening commitment (looking it up on chain once for channels stored without one) and reject primitive vouchers on channels the escrow bound to a configurable account.
