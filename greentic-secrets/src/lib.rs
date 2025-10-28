pub use greentic_secrets_core as core;
pub use greentic_secrets_spec as spec;
pub use greentic_secrets_support as support;

#[cfg(feature = "providers-aws")]
pub use greentic_secrets_provider_aws_sm as aws;
#[cfg(feature = "providers-azure")]
pub use greentic_secrets_provider_azure_kv as azure;
#[cfg(feature = "providers-dev")]
pub use greentic_secrets_provider_dev as dev;
#[cfg(feature = "providers-gcp")]
pub use greentic_secrets_provider_gcp_sm as gcp;
#[cfg(feature = "providers-k8s")]
pub use greentic_secrets_provider_k8s as k8s;
#[cfg(feature = "providers-vault")]
pub use greentic_secrets_provider_vault_kv as vault;
