---
pympp: major
---

Added `NoMethodFoundError`, `ChallengeCandidate`, `OrderChallenges`, `RemoteFeePayer`, `ChargeMode`, and `ProofCredentialPayload` to the public API, and added `order_challenges` parameter to `PaymentTransport`, `Mpp`, and `McpClient`. Removed `feePayerUrl` from `MethodDetails` and changed `PaymentTransport` behavior so an unpayable 402 now raises `NoMethodFoundError` instead of returning the response, matching mppx.
