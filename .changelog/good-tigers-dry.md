---
pympp: minor
---

Added MPP session server support for the Tempo payment channel protocol, introducing a comprehensive set of new public modules and APIs (`mpp.methods.tempo.session`, `mpp.methods.tempo.session.abi`, `mpp.methods.tempo.session.chain`, `mpp.methods.tempo.session.protocol`, `mpp.methods.tempo.session.server`, and related submodules) for managing payment channel lifecycles including open, top-up, settle, close, and voucher operations. Also added CI support for mppx session interop harness tests.
