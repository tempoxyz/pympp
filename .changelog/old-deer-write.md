---
pympp: minor
---

Fixed session top-ups to preserve the `auto_swap` swap policy from `SessionContext` when performing automatic channel top-ups. Added optional `auto_swap: bool | AutoSwap | None = None` parameter to the public `top_up_channel_if_needed` and `post_top_up` methods to allow callers to explicitly pass a swap policy override.
