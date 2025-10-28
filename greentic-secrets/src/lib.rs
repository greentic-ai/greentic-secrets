pub use greentic_secrets_core as core;
pub use greentic_secrets_spec as spec;

#[cfg(feature = "providers-aws")]
pub use greentic_secrets_provider_aws as aws;
#[cfg(feature = "providers-azure")]
pub use greentic_secrets_provider_azure as azure;
#[cfg(feature = "providers-dev")]
pub use greentic_secrets_provider_dev_env as dev;
#[cfg(feature = "providers-gcp")]
pub use greentic_secrets_provider_gcp as gcp;
#[cfg(feature = "providers-k8s")]
pub use greentic_secrets_provider_k8s as k8s;
#[cfg(feature = "providers-vault")]
pub use greentic_secrets_provider_vault as vault;
