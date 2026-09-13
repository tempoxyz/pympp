---
pympp: patch
---

Fixed WWW-Authenticate parsing to restore characters above Latin-1. Header values cannot carry them directly, so challenges escape them as `\uXXXX`; those escapes were previously decoded as the literal text `u2014` rather than as `—`. Surrogate pairs are recombined, and an unpaired surrogate becomes U+FFFD.
