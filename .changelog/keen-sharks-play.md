---
pympp: patch
---

Improved error messages for missing optional extras by adding an `install_hint` context manager that names the required `pympp[extra]` when direct submodule imports fail. Also removed pinned transitive dependencies (`propcache`, `urllib3`, `yarl`) from optional extras, updated the README quickstart with a complete working example, and corrected the default RPC URL in docs and examples to the Tempo mainnet endpoint.
