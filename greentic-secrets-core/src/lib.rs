//! Core domain primitives shared across brokers, SDKs, and providers.

pub mod backend;
pub mod broker;
pub mod crypto;
pub mod embedded;
pub mod errors;
#[cfg(feature = "imds")]
pub mod imds;
pub mod key_provider;
pub mod policy;
pub mod probe;
pub mod provider;
pub mod resolver;
pub mod spec;
pub mod spec_registry;
pub mod spec_schema;
pub mod spec_validate;
pub mod types;
pub mod uri;

pub use crate::spec_registry::SecretSpecRegistry;
pub use crate::spec_schema::specs_to_json_schema;
pub use crate::spec_validate::SecretValidationResult;
#[cfg(feature = "aws")]
pub use backend::aws::AwsSecretsManagerBackend;
#[cfg(feature = "env")]
pub use backend::env::EnvBackend;
#[cfg(feature = "file")]
pub use backend::file::FileBackend;
#[cfg(feature = "k8s")]
pub use backend::k8s::K8sBackend;
pub use backend::{SecretVersion, SecretsBackend, VersionedSecret};
pub use broker::{BrokerSecret, SecretsBroker};
pub use crypto::dek_cache::DekCache;
pub use crypto::envelope::EnvelopeService;
pub use embedded::{
    CoreBuilder, CoreConfig, MemoryBackend, MemoryKeyProvider, Policy, SecretsCore, SecretsError,
};
pub use errors::{DecryptError, DecryptResult, Error, Result};
pub use key_provider::KeyProvider;
pub use policy::{Authorizer, PolicyGuard, Principal};
pub use provider::Provider;
pub use resolver::{DefaultResolver, ResolverConfig};
pub use spec::{SecretDescribable, SecretSpec};
pub use types::{
    ContentType, EncryptionAlgorithm, Envelope, Scope, SecretIdentifier, SecretListItem,
    SecretMeta, SecretRecord, Visibility,
};
pub use uri::SecretUri;
