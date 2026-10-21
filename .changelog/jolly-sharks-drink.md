---
pympp: patch
---

Parallelized CI by splitting lint/type-check into its own job, added `pytest-xdist` for parallel test execution, and overlapped Docker image pulls with environment setup in the integration job. Also switched package builds to use `uv build` directly.
