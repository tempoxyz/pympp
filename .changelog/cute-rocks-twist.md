---
pympp: patch
---

Added a public API snapshot (`api/public-api.txt`) with a CI check to detect unintended API changes, and improved the CI coverage pipeline by adding branch coverage ratcheting, diff-cover checks for changed lines, and Redis service containers for all test matrix runs.
