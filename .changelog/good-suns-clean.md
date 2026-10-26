---
pympp: patch
---

Fixed several correctness issues in the server engine. Out-of-band `validate_credential` and `broadcast_credential` no longer guess between separately configured methods that share the credential's name and intent (they may settle through different replay stores): pass `request=` and it must match exactly one of them, or the credential is refused; copies from one configuration, such as one per accepted currency, still settle without it. Custom scope matching is now enforced during credential verification, percent-encoded URL paths stay distinct in signed scopes and resource fields, header encoding handles non-ASCII bytes, and intent callbacks must return `Validation` results.
