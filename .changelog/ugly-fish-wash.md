---
pympp: patch
---

Used the bootstrapped Tempo localnet image for reproducible integration tests, replacing the dynamic `latest` tag pull-and-cache approach with a pinned `tempo-localnet` image digest. Removed the dev-key-based account funding fallback in favour of exclusively using the localnet faucet via `tempo_fundAddress`.
