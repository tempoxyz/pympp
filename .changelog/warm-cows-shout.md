---
pympp: patch
---

Preserved streaming bodies for unmatched 402 responses. Released matched response streams before credential callbacks, closed owned responses on cancellation, and preserved primary errors when cleanup failed. Matched challenges rejected during credential creation now return a readable empty 402 response after their original body has been discarded.
