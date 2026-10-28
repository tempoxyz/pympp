---
pympp: minor
---

Added x402 v2 client support to `mpp.x402`, exposing `X402Challenge`, `x402_challenges`, `is_x402_challenge`, and `payment_response` as new public API. Added a complete `examples/x402-client/` example demonstrating a pympp client paying a Coinbase x402 server on a local Anvil chain.
