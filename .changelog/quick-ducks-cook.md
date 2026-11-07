---
pympp: minor
---

Added `PaymentSimulationError`, a new public exception class (subclass of `VerificationError`) that is raised when a sponsored transaction fails its pre-broadcast `eth_call` simulation. The error tags the failing phase (`"sender"` or `"sponsored"`), sender address, fee payer, and payment token, matching the structure of mppx's `preflightSponsorship` errors to allow callers to distinguish payer failures from sponsor failures without parsing node messages. A node rejection other than an execution failure, such as a sponsor's insufficient fee token balance, still raises `InternalPaymentError`, with the tagged `PaymentSimulationError` as its cause, as mppx does.
