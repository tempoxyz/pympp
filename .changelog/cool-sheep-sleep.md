---
pympp: patch
---

Paid requests rejected with a 401 that carries no receipt are now resent once with refreshed identity headers and the same Payment credential while the Challenge has not expired.
