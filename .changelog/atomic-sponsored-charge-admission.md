---
"pympp": patch
---

Bind local sponsored charges to a single transaction per challenge and serialize pending charges per payer and currency before simulation. Preserve claims through unknown outcomes. Configured stores now require compare-and-set support for local sponsorship; use a shared atomic backend across instances.
