---
pympp: major
---

Rebuilt the SDK on the mppx engine model, aligning wire formats, defaults, validation, and error types with the TypeScript reference SDK. Dropped Python 3.11 support, removed the Stripe CI profile, overhauled the public API surface (new module paths: `mpp.tempo`, `mpp.evm`, `mpp.mcp_sdk`), and added architecture documentation alongside a migration guide from pympp 0.15.
