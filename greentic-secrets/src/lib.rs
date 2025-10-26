pub use greentic_secrets_core as core;
pub use greentic_secrets_spec as spec;
pub use greentic_secrets_support as support;

#[cfg(feature = "providers-aws")]
pub use greentic_secrets_provider_aws_sm as provider_aws_sm;
#[cfg(feature = "providers-azure")]
pub use greentic_secrets_provider_azure_kv as provider_azure_kv;
#[cfg(feature = "providers-dev")]
pub use greentic_secrets_provider_dev as provider_dev;
#[cfg(feature = "providers-gcp")]
pub use greentic_secrets_provider_gcp_sm as provider_gcp_sm;
#[cfg(feature = "providers-k8s")]
pub use greentic_secrets_provider_k8s as provider_k8s;
#[cfg(feature = "providers-vault")]
pub use greentic_secrets_provider_vault_kv as provider_vault_kv;
