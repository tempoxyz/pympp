---
pympp: patch
---

Fixed handling of 402 payment challenge responses to avoid buffering the response body, ensuring the stream remains available to the caller. Improved cleanup logic to properly close responses on cancellation or error, and moved response closing to the correct locations in the payment flow.
