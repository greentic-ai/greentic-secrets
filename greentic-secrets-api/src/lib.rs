#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::{borrow::Cow, string::String, vec::Vec};

use async_trait::async_trait;
use thiserror::Error;

#[cfg(feature = "std")]
use anyhow::Error as AnyhowError;

/// Error conditions that can occur while interacting with a secrets provider.
#[derive(Debug, Error)]
pub enum SecretError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied: {0}")]
    Permission(String),

    #[error("backend error: {0}")]
    Backend(Cow<'static, str>),

    #[cfg(feature = "std")]
    #[error(transparent)]
    Other(#[from] AnyhowError),
}

/// Result type returned by [`SecretsManager`].
pub type Result<T> = core::result::Result<T, SecretError>;

/// Minimal secrets manager interface shared between hosts and providers.
#[async_trait]
pub trait SecretsManager: Send + Sync {
    /// Read the secret data stored at `path`.
    async fn read(&self, path: &str) -> Result<Vec<u8>>;

    /// Overwrite the secret data stored at `path`.
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()>;

    /// Delete the secret stored at `path`.
    async fn delete(&self, path: &str) -> Result<()>;
}
