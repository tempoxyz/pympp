---
pympp: patch
---

Added property-based tests for the server engine, challenge binding, and unit conversion, along with concurrency stress tests covering exactly-once settlement, replay-store claims, and client transport credential isolation. Registered a new `stress` pytest marker for heavy concurrency runs gated behind `MPP_STRESS=1`.
