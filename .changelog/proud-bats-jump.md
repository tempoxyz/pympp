---
pympp: patch
---

Fixed a race condition in Zone sender tag derivation where a slow retry could overwrite a newer block's tags with older ones, using compare-and-swap semantics instead of block hash comparison. Improved error messages for underivable sender tags to report the specific reason (no withdrawal found, or too many candidates).
