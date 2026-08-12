---
pympp: minor
---

Added a `VerifiableIntent` protocol with separate `validate` and `broadcast` hooks plus bound `Mpp.validate_credential()` and `Mpp.broadcast_credential()` APIs, introduced a `Relay` adapter that delegates Tempo charge validation and finalization to the Tempo API relay (surfacing only safe machine-readable error codes and retryable 402 challenges on decline), and added a runnable `charge-relay` FastAPI example with a payer client. Relay idempotency keys use the `pympp_` namespace, existing Stripe idempotency behavior remains unchanged, and Python validation details use snake_case.
