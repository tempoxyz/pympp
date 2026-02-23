---
pympp: patch
---

Added pyright, build, and twine as dev dependencies. Improved CI pipeline with separate lint, test, and package jobs, concurrency cancellation, coverage enforcement, and package validation. Fixed pyright type errors with `type: ignore` annotations and refactored `ChargeIntent` to use a `_get_rpc_url()` helper to safely unwrap the optional RPC URL.
