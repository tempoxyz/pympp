---
pympp: minor
---

Added support for machine-token (MACH) charge payments via a new `_machine_token` module implementing first-party swapper routes. Added `machineTokenEnabled` field to `MethodDetails` and `ChargeInput` schemas, and a `machine_token_enabled` parameter to the `charge()` server function, enabling clients holding MACH to pay through the canonical swapper which atomically settles the charge currency to the recipient.
