---
pympp: minor
---

Added support for resending paid requests after a 401 response that carries no settlement receipt and while the Challenge has not expired, since servers check other authentication before verifying a Payment credential (meaning a 401 never follows settlement). A rejected paid response body is buffered (up to 64 KiB, with a 2-second timeout) and returned as a fallback if the resend cannot proceed.
