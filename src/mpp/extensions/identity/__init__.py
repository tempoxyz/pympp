"""Identity providers for :mod:`mpp.identity`, one module per protocol (mppx `extensions/identity`).

- :mod:`mpp.extensions.identity.tempo`: Tempo ID access tokens, with DPoP (``pympp[tempo-id]``).
- :mod:`mpp.extensions.identity.persona`: Persona KYC, a payment check that requires an approved
  Persona inquiry.

Not yet ported from mppx (TODO): attestation and email OTP (Ed25519 attestation tokens), Link,
RFC 9421 HTTP message signatures with Web Bot Auth and TAP on top, World ID, and the
onchain registry check. Each plugs into the same :class:`~mpp.identity.Verifier`,
:class:`~mpp.identity.PaymentCheck` and :class:`~mpp.identity.Prover` types.
"""
