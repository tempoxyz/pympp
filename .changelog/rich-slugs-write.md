---
pympp: minor
---

Added `fee_policy` parameter to `charge()` and `payer_fee_policy` field on `TempoMethod` for client-controlled per-gas, priority, and total-fee ceilings on unsponsored Tempo transactions. Enforced default payer fee budgets in both the charge client and session layer, rejecting excessive RPC gas-price quotes and worst-case total fees before signing.
