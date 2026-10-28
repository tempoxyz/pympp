---
pympp: patch
---

Added nightly mutation testing (mutmut) and coverage-guided fuzzing (atheris) infrastructure for protocol-critical modules. Includes GitHub Actions workflows, Makefile targets, fuzz harnesses for header parsers and transaction decoders, and a Hypothesis profile for deterministic mutation test runs.
