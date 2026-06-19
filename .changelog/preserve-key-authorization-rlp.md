---
pympp: patch
---

Preserve all sender-signed fields when decoding and re-signing fee-payer (0x78) envelopes. Two fields that are part of the sender's signing hash were being lost when the fee payer reconstructed the transaction to cosign it, causing valid transactions to be rejected ("Sender address does not match recovered signer") or mis-attributed:

- **`keyAuthorization`**: the decoder rebuilt it from only `chain_id`, `key_type`, `key_id`, and `expiry`, dropping `limits` and the T6 (TIP-1049) `allowed_calls`, `witness`, `is_admin`, and `account` fields. It now round-trips the authorization RLP verbatim (decode and encode), so it works for both legacy and T6 authorizations — including non-secp256k1 root signatures — without requiring a T6-aware `pytempo`.
- **`tempo_authorization_list`**: was dropped entirely during cosigning; it is now carried through.

Access-key (keychain) and other non-secp256k1 sender signatures, which a fee payer cannot verify offline, are now rejected with a clear error instead of an opaque ECDSA recovery failure, and the envelope decoder fails closed on unexpected field counts.

Pre-broadcast simulation (`tempo_simulateV1`) is skipped for locally co-signed transactions that carry a `keyAuthorization` or a non-empty `tempo_authorization_list`. These fields are preserved verbatim as opaque RLP for the broadcast transaction but cannot yet be faithfully re-serialized into the simulation JSON (`keyAuthorization` / `aaAuthorizationList`), so the transaction is broadcast without the extra revert check rather than simulated as a different transaction.
