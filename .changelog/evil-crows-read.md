---
pympp: major
---

Changed `SessionManager.fetch()` to pin each manager instance to the HTTP origin of its first request, rejecting requests to any other origin with a `ValueError`. Redirects are no longer followed even when `follow_redirects=True` is passed (a 3xx response is returned instead), preventing session credentials from leaking to a different origin. Added an `origin` field to `ChannelEntry` so stored channels are bound to their manager's origin, and reopening a channel from a different origin now raises rather than silently reusing the credential.
