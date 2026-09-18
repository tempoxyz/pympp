---
pympp: minor
---

Remove custom primary Tempo charge memos. Clients always generate attribution memos bound to the challenge and realm, and servers always verify that binding. Remove the `memo` charge option and `MethodDetails.memo`; split-specific memos remain supported.
