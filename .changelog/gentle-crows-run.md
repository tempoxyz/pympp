---
pympp: patch
---

Fixed optional dependency handling by converting eager imports in `mpp.extensions.mcp` and `mpp.methods.tempo` to lazy `__getattr__`-based loading, so importing these modules without their extras installed no longer raises `ImportError` at import time. Added clear install hint messages when optional attrs are accessed without the required extras, and added `eth-account`, `eth-hash`, `attrs`, and `rlp` as declared dependencies for the `[tempo]` extra.
