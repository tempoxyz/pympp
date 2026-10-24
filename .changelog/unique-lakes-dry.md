---
pympp: minor
---

Added a required `store` parameter to `MachinePayments.create()` and `TempoPayments` to inject a shared atomic replay store, enabling Tempo charge intents to reject replayed transaction hashes across server replicas. Added validation that the provided store implements `put_if_absent` and updated tests to cover the new replay-protection behavior.
