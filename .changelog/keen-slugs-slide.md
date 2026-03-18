---
pympp: patch
---

Updated `examples/api-server/README.md` to replace references to the external `purl` tool with the `pympp` client (`python -m mpp.fetch`) and corrected the `secret_key` documentation to reflect that it is read from the `MPP_SECRET_KEY` env var rather than auto-generated.
