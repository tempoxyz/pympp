---
pympp: patch
---

Added Stripe Connect settlement (`connect`) to Stripe SPT charges and to Tempo payments recorded through `MachinePayments`. The settlement stays server-side, out of the challenge, and is validated before the payment settles.
