---
pympp: patch
---

Local fee sponsorship now verifies the sender signature with pytempo before co-signing: secp256k1, P256, WebAuthn and keychain (access-key) senders are accepted when their signature verifies, and multisig or forged envelopes are refused. As in mppx, an access key's expiry, revocation and spending limits are left to the chain, so a local sponsor can pay gas for an over-limit keychain transfer that reverts; use a hosted sponsor that enforces access-key limits to avoid that.
