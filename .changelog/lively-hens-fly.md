---
pympp: minor
---

Restricted payment method names to lowercase letters (a-z), as the spec requires: parsing and formatting a Challenge now reject any other name, and `Mpp` refuses one at startup. Custom methods that use digits, hyphens, underscores, colons or capitals must be renamed.
