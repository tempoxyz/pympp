---
pympp: patch
---

Stopped reading `HOST` and `HOSTNAME` for realm auto-detection. Container runtimes set `HOSTNAME` per replica, so replicas issued challenges under different realms and rejected each other's credentials. Set `MPP_REALM` or pass `realm` to keep a host-based realm.
