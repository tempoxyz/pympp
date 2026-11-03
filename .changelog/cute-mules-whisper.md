---
pympp: minor
---

Added `fee_token` parameter to the `charge` client method, allowing callers to explicitly specify the token used to pay transaction fees for unsponsored charges. This is useful for access keys whose spending limits do not cover the default fee token.
