---
pympp: patch
---

Rejected challenges whose `header` auth-param is anything but `Payment-Authorization` (ASCII case-insensitive), and made a constructed challenge raise `ValueError` for any other value, including an empty one. A received challenge's `header` is now echoed in its credential exactly as the server spelled it, while locally created challenges emit the canonical `Payment-Authorization`.
