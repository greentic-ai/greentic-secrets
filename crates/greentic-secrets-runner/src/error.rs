use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecretError {
    #[error("secret `{key}` is not allowed by policy")]
    Denied { key: String },
    #[error("secret `{key}` not found in environment")]
    NotFound { key: String },
}

impl SecretError {
    pub fn code(&self) -> &'static str {
        match self {
            SecretError::Denied { .. } => "denied",
            SecretError::NotFound { .. } => "not_found",
        }
    }
}
