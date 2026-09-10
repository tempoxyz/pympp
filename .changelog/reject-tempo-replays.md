---
pympp: patch
---

Rejected reused Tempo transaction credentials and enabled in-memory replay protection by default. Configure a shared persistent store for deployments with multiple replicas or restarts.

Bounded the default replay store to 10,000 entries without evicting used hashes, and released reservations after inconclusive receipt lookups so payments can be retried safely.
