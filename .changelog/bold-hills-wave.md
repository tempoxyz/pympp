---
pympp: patch
---

Added a test to verify that the HTTP client preserves the original request method, URL, headers, and body when retrying a request after receiving a 402 payment-required response.
