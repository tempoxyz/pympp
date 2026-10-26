---
pympp: patch
---

Fixed several correctness issues in the server engine: percent-encoded URL paths are now preserved distinctly in signed scopes and resource fields, challenges from servers configuring several methods of one name and intent carry a signed issuing-method tag, so out-of-band settlement uses the issuing method's replay store and cannot accept a payment twice, and custom scope matching is enforced during credential verification. Also fixed header encoding for non-ASCII bytes and added validation that intent callbacks return proper `Validation` results.
