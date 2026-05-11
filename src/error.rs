use thiserror::Error;

pub type Result<T> = core::result::Result<T, ArcError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ArcError {
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("invalid element encoding")]
    InvalidElement,

    #[error("invalid scalar encoding")]
    InvalidScalar,

    #[error("invalid proof length: expected {expected} bytes, got {actual}")]
    InvalidProofLength { expected: usize, actual: usize },

    #[error("proof verification failed")]
    ProofVerificationFailed,

    #[error("presentation limit exceeded")]
    LimitExceeded,

    #[error("invalid presentation limit")]
    InvalidPresentationLimit,

    #[error("invalid range proof")]
    InvalidRangeProof,

    #[error("internal proof statement is malformed")]
    MalformedStatement,
}
