---
pympp: minor
---

Added a `SplitIntent` protocol with split `validate_credential`/`broadcast_credential` lifecycle APIs to separate non-mutating validation from terminal settlement, introduced a `Relay` adapter that delegates Tempo charge validation and finalization to the Tempo API relay (surfacing only safe machine-readable error codes and retryable 402 challenges on decline), and added a runnable `charge-relay` FastAPI example with a payer client. Relay and Stripe idempotency keys now use the `pympp_` namespace, internal route scope uses `_mpp_scope`, and Python validation details use snake_case.
