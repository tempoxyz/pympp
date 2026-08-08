---
pympp: patch
---

Fixed handling of fresh 402 payment challenges returned after a paid retry, enabling clients to recover from failed verification and complete multi-round payment flows. Introduced a retry loop with a maximum attempt limit to support these sequential challenge-response exchanges.
