#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod backend;
pub mod error;
pub mod helpers;
pub mod key_provider;
pub mod result_ext;
pub mod serde_util;
pub mod types;
pub mod uri;

pub use backend::{SecretVersion, SecretsBackend, VersionedSecret};
pub use error::{DecryptError, DecryptResult, Error, Result, SecretsError, SecretsResult};
pub use helpers::*;
pub use key_provider::*;
pub use result_ext::*;
pub use serde_util::*;
pub use types::*;
pub use uri::*;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

pub type DynSecretsBackend = Arc<dyn SecretsBackend + Send + Sync>;

pub mod prelude {
    pub use crate::uri::*;
    pub use crate::ResultExt;
    pub use crate::{
        record_from_plain, with_ttl, Envelope, KeyProvider, SecretIdentifier, SecretListItem,
        SecretMeta, SecretRecord, SecretsBackend, SecretsError, SecretsResult,
    };
}
