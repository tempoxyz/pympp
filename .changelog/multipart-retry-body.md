---
pympp: patch
---

Handle multipart (`files=`) and streaming bodies on paid 402 retry. Multipart bodies are buffered and replayed identically; async generator bodies raise `PaymentError` before any I/O.
