use thiserror::Error;

/// Result alias for domain operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Result alias for decryption operations.
pub type DecryptResult<T> = std::result::Result<T, DecryptError>;

/// Core domain error variants.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// Secret identifier was empty or otherwise invalid.
    #[error("secret identifier must not be empty")]
    InvalidIdentifier,
    /// Component failed validation due to unexpected characters.
    #[error("{field} contains invalid characters: {value}")]
    InvalidCharacters {
        /// Name of the component.
        field: &'static str,
        /// Offending value.
        value: String,
    },
    /// Component must not be empty.
    #[error("{field} must not be empty")]
    EmptyComponent {
        /// Name of the component.
        field: &'static str,
    },
    /// URI scheme must always be `secrets`.
    #[error("uri must start with secrets://")]
    InvalidScheme,
    /// URI was missing the specified segment.
    #[error("uri is missing {field}")]
    MissingSegment {
        /// Name of the missing segment.
        field: &'static str,
    },
    /// URI contained more segments than expected.
    #[error("uri contains unexpected extra segments")]
    ExtraSegments,
    /// Version component failed validation.
    #[error("invalid version segment: {value}")]
    InvalidVersion {
        /// Offending value.
        value: String,
    },
    /// Requested encryption algorithm is not recognised.
    #[error("encryption algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),
    /// Algorithm requires a feature that is not compiled in.
    #[error("encryption algorithm {0} requires the 'xchacha' feature")]
    AlgorithmFeatureUnavailable(String),
    /// Low-level crypto failure.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Backing store failed to satisfy the request.
    #[error("storage error: {0}")]
    Storage(String),
    /// Requested entity could not be found.
    #[error("{entity} not found")]
    NotFound {
        /// Name of the missing entity (usually a URI).
        entity: String,
    },
}

/// Fine grained errors emitted by decrypt operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecryptError {
    /// Authentication tag mismatch or tampered ciphertext.
    #[error("message authentication failed")]
    MacMismatch,
    /// Key provider returned an error.
    #[error("key provider error: {0}")]
    Provider(String),
    /// Envelope was malformed or missing required fields.
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    /// Generic crypto failure.
    #[error("crypto error: {0}")]
    Crypto(String),
}
