---
pympp: patch
---

Fixed realm detection to ignore `HOST` and `HOSTNAME` environment variables, preventing container replicas from generating conflicting realm values that would cause credentials to be rejected across replicas. Added tests to verify `HOST`/`HOSTNAME` are ignored and that platform-specific variables (e.g. `RENDER_EXTERNAL_HOSTNAME`) take precedence correctly.
