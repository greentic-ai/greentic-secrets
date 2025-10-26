#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod backend;
pub mod error;
pub mod types;
pub mod uri;

pub use backend::{SecretVersion, SecretsBackend, VersionedSecret};
pub use error::{DecryptError, DecryptResult, Error, Result, SecretsError, SecretsResult};
pub use types::*;
pub use uri::*;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

pub type DynSecretsBackend = Arc<dyn SecretsBackend + Send + Sync>;

pub mod prelude {
    pub use crate::uri::*;
    pub use crate::{Envelope, SecretIdentifier, SecretListItem, SecretMeta, SecretRecord};
    pub use crate::{SecretsBackend, SecretsError, SecretsResult};
}
