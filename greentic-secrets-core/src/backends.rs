//! Re-export of feature-gated backend implementations for ergonomic imports.

#[cfg(feature = "aws")]
pub use crate::backend::aws::AwsSecretsManagerBackend;
#[cfg(feature = "azure")]
pub use crate::backend::azure::AzureKeyVaultBackend;
#[cfg(feature = "env")]
pub use crate::backend::env::EnvBackend;
#[cfg(feature = "file")]
pub use crate::backend::file::FileBackend;
#[cfg(feature = "gcp")]
pub use crate::backend::gcp::GcpSecretsManagerBackend;
#[cfg(feature = "k8s")]
pub use crate::backend::k8s::K8sBackend;
