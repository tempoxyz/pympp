---
pympp: patch
---

Migrated hash-verification tests from mocked unit tests to live integration tests against a real Tempo devnet, and added a CI workflow job to run them in a Docker environment with caching for the Tempo image. Removed the mocked `test_stores_redis.py` file.
