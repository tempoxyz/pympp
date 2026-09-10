---
pympp: patch
---

Rejected replayed Tempo transaction credentials by raising a `VerificationError` instead of silently fetching the existing receipt, and enabled in-memory replay protection by default when no store is configured. Updated tests to reflect the stricter duplicate-rejection behavior and corrected transaction hash fixtures to use deterministic values.
