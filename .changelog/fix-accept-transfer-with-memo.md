---
pympp: patch
---

fix: accept `transferWithMemo` calls in pre-broadcast validation when no explicit memo is required

Aligns with mppx behavior — clients may auto-generate attribution memos via `transferWithMemo` even when the server request has no explicit memo. Previously, the server would reject these with `VerificationError: Invalid transaction: no matching payment call found`.
