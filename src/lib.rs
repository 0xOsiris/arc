//! Anonymous Rate-Limited Credentials (ARC) for the draft `ARCV1-P256`
//! ciphersuite.

pub mod error;
pub mod group;
mod proof;
mod protocol;
mod range;

pub use error::{ArcError, Result};
pub use group::{
    CONTEXT_STRING, Element, NE, NS, Scalar, generator_g, generator_h, hash_to_group,
    hash_to_scalar, random_scalar, scalar_from_bytes, scalar_to_bytes,
};
pub use protocol::{
    ClientSecrets, Credential, CredentialRequest, CredentialResponse, Presentation,
    PresentationProof, PresentationState, ServerPrivateKey, ServerPublicKey,
    finalize_credential, request_credential, respond_credential, setup_server,
    verify_credential_request, verify_credential_response, verify_presentation,
};

#[cfg(test)]
mod tests;
