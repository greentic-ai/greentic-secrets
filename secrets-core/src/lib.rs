//! Core domain primitives shared across brokers, SDKs, and providers.

pub mod backend;
pub mod broker;
pub mod crypto;
pub mod errors;
pub mod key_provider;
pub mod policy;
pub mod types;
pub mod uri;

pub use backend::{SecretVersion, SecretsBackend, VersionedSecret};
pub use broker::{BrokerSecret, SecretsBroker};
pub use crypto::dek_cache::DekCache;
pub use crypto::envelope::EnvelopeService;
pub use errors::{DecryptError, DecryptResult, Error, Result};
pub use key_provider::KeyProvider;
pub use policy::{Authorizer, PolicyGuard, Principal};
pub use types::{
    ContentType, EncryptionAlgorithm, Envelope, Scope, SecretIdentifier, SecretListItem,
    SecretMeta, SecretRecord, Visibility,
};
pub use uri::SecretUri;
