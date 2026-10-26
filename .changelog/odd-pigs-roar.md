---
pympp: minor
---

Added request attestation support via a new `mpp.attestation` module, including RFC 9421 HTTP message signing and verification for the Trusted Agent Protocol (TAP) and Web Bot Auth (HTTPS-directory profile). The new functionality is available via the optional `attestation` extra (`pip install pympp[attestation]`).
