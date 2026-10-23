---
pympp: patch
---

Raised the Authorization credential size limit from 16 KiB to 64 KiB, matching mppx, and applied the size check to the raw header before scheme extraction. Fixed rejections of valid credentials whose size exceeded the old limit due to echoing large challenge requests or `opaque` values.
