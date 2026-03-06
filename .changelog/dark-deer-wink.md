---
pympp: minor
---

Consolidated `expires` from the request body into the challenge-level `expires` auth-param exclusively. Removed `expires` as a field from `ChargeRequest` schema and updated all server, intent, and test code to read expiry from `credential.challenge.expires` instead.
