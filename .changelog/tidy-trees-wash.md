---
pympp: patch
---

Fixed split memos using the MPP attribution format are now rejected before challenge issuance and before client payment, so a fixed split leg can't also pay another challenge. Servers check every Tempo charge issuance path (`Mpp`, `verify_or_challenge`, the `pay` decorator and MCP `create_challenge`), and clients skip such offers during challenge selection. Removed the `fixed` exemption from MPP memo binding checks, so every matched transfer carrying an MPP attribution memo must be bound to the current challenge and realm, matching mppx. Credentials for outstanding challenges with fixed MPP memos fail with `CredentialReplayedError`.
