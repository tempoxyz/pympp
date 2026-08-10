---
pympp: patch
---

Fixed challenge selection to match on both method name and intent, preventing methods from being incorrectly matched to challenges with unsupported intents. Added `intents` property to the `Method` protocol to declare which payment intents each method supports.
