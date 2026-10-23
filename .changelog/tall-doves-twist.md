---
pympp: patch
---

Fixed a security vulnerability where a split-charge payment leg carrying an MPP attribution memo bound to a different challenge or realm could be used to authorize unintended charges. Now any MPP memo found in matched transfer logs must be bound to the current challenge and realm, or a `CredentialReplayedError` is raised; plain transfers and non-MPP memos remain allowed.
