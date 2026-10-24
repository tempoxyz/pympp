---
pympp: patch
---

Fixed challenge expiry enforcement to treat the exact expiry instant as expired by changing strict less-than comparisons (`<`) to less-than-or-equal (`<=`) across all expiry checks. Added a pre-broadcast expiry recheck in Tempo's `ChargeIntent` to prevent settling transactions whose challenges expired during sponsorship or simulation, and introduced a shared `_challenge_expired` helper. Added tests to cover both scenarios.
