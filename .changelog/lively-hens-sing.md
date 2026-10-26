---
pympp: minor
---

Added `ConnectSettlement` and `TransferData` public types for Stripe Connect destination-charge routing, and wired an optional `connect` parameter through `charge()`, `MachinePayments`, `SptPayments`, `TempoPayments`, and `record_crypto_payment()`. Added `AutoSwap` and `InsufficientFundsError` to the Tempo client so a payer can automatically buy a missing charge currency through the stablecoin DEX in the same transaction, and corrected the `SWAP_EXACT_AMOUNT_OUT_SELECTOR` function selector.
