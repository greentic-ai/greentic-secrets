#[cfg(feature = "use_spec")]
pub use greentic_secrets_spec::{
    DecryptError, DecryptResult, Error, Result, SecretsError, SecretsResult,
};

#[cfg(not(feature = "use_spec"))]
mod legacy {
    use thiserror::Error;

    pub type Result<T> = std::result::Result<T, Error>;
    pub type DecryptResult<T> = std::result::Result<T, DecryptError>;

    #[derive(Debug, Clone, PartialEq, Eq, Error)]
    pub enum Error {
        #[error("secret identifier must not be empty")]
        InvalidIdentifier,
        #[error("{field} contains invalid characters: {value}")]
        InvalidCharacters { field: &'static str, value: String },
        #[error("{field} must not be empty")]
        EmptyComponent { field: &'static str },
        #[error("uri must start with secrets://")]
        InvalidScheme,
        #[error("uri is missing {field}")]
        MissingSegment { field: &'static str },
        #[error("uri contains unexpected extra segments")]
        ExtraSegments,
        #[error("invalid version segment: {value}")]
        InvalidVersion { value: String },
        #[error("encryption algorithm not supported: {0}")]
        UnsupportedAlgorithm(String),
        #[error("encryption algorithm {0} requires the 'xchacha' feature")]
        AlgorithmFeatureUnavailable(String),
        #[error("crypto error: {0}")]
        Crypto(String),
        #[error("storage error: {0}")]
        Storage(String),
        #[error("{entity} not found")]
        NotFound { entity: String },
    }

    #[derive(Debug, Clone, PartialEq, Eq, Error)]
    pub enum DecryptError {
        #[error("message authentication failed")]
        MacMismatch,
        #[error("key provider error: {0}")]
        Provider(String),
        #[error("invalid envelope: {0}")]
        InvalidEnvelope(String),
        #[error("crypto error: {0}")]
        Crypto(String),
    }

    pub type SecretsResult<T> = Result<T>;
    pub type SecretsError = Error;
}

#[cfg(not(feature = "use_spec"))]
pub use legacy::*;
