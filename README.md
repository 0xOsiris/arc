Rust implementation of the `ARCV1-P256` ciphersuite for Anonymous
Rate-Limited Credentials (ARC).

This crate follows the IETF Privacy Pass working group draft:
[Anonymous Rate-Limited Credentials Cryptography][arc-draft].

## ⚠️ Disclaimer

This project is a proof of concept. It is not ready for production use, and has not
been audited

## Scope

The library implements the cryptographic protocol flow for ARC:

- server key generation
- credential request creation and verification
- credential issuance and finalization
- credential presentation with nonce range proofs
- presentation verification
- byte serialization for the public wire types

The implementation is currently focused on `ARCV1-P256`; it is not a
networked issuer or verifier service.

[arc-draft]: https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html
