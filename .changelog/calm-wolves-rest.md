---
pympp: minor
---

Added the public `mpp.methods.tempo.attribution` module, exposing `encode`, `decode`, `DecodedMemo`, `is_mpp_memo`, `verify_server`, and `verify_challenge_binding` for identifying and reconciling MPP attribution memos on Tempo transfers. Added docstrings to all public functions and the `DecodedMemo` dataclass, and updated tests to import from the new public module.
