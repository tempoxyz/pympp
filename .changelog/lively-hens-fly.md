---
pympp: minor
---

Payment method names are now limited to lowercase letters (a-z), as the spec requires: parsing and formatting a Challenge reject any other name, and `Mpp` refuses one at startup. Rename custom methods that use digits, hyphens, underscores, colons or capitals.
