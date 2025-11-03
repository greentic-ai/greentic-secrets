use anyhow::{Context, Result, anyhow};
use secrets_core::backend::SecretsBackend;
use secrets_core::key_provider::KeyProvider;

pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

pub async fn load_backend_components() -> Result<BackendComponents> {
    let backend_kind = std::env::var("SECRETS_BACKEND").unwrap_or_else(|_| "dev".into());
    match backend_kind.as_str() {
        "dev" => dev_backend().await,
        "aws" => {
            #[cfg(feature = "aws-sm")]
            {
                aws_backend().await
            }

            #[cfg(not(feature = "aws-sm"))]
            {
                anyhow::bail!("aws backend requested but aws-sm feature is not enabled");
            }
        }
        "gcp" => {
            #[cfg(feature = "gcp-sm")]
            {
                gcp_backend().await
            }

            #[cfg(not(feature = "gcp-sm"))]
            {
                anyhow::bail!("gcp backend requested but gcp-sm feature is not enabled");
            }
        }
        "azure" => {
            #[cfg(feature = "azure-kv")]
            {
                azure_backend().await
            }

            #[cfg(not(feature = "azure-kv"))]
            {
                anyhow::bail!("azure backend requested but azure-kv feature is not enabled");
            }
        }
        "k8s" => {
            #[cfg(feature = "k8s")]
            {
                k8s_backend().await
            }

            #[cfg(not(feature = "k8s"))]
            {
                anyhow::bail!("k8s backend requested but k8s feature is not enabled");
            }
        }
        "vault" => {
            #[cfg(feature = "vault-kv")]
            {
                vault_backend().await
            }

            #[cfg(not(feature = "vault-kv"))]
            {
                anyhow::bail!("vault backend requested but vault-kv feature is not enabled");
            }
        }
        other => Err(anyhow!("unsupported backend `{other}`")),
    }
}

async fn dev_backend() -> Result<BackendComponents> {
    let backend = secrets_provider_dev::DevBackend::from_env()
        .context("failed to configure development backend")?;
    let provider = secrets_provider_dev::DevKeyProvider::from_env();

    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(provider),
    })
}

#[cfg(feature = "aws-sm")]
async fn aws_backend() -> Result<BackendComponents> {
    let components = secrets_provider_aws_sm::build_backend()
        .await
        .context("failed to initialize aws secrets backend")?;
    Ok(BackendComponents {
        backend: components.backend,
        key_provider: components.key_provider,
    })
}

#[cfg(feature = "gcp-sm")]
async fn gcp_backend() -> Result<BackendComponents> {
    let components = secrets_provider_gcp_sm::build_backend()
        .await
        .context("failed to initialize gcp secrets backend")?;
    Ok(BackendComponents {
        backend: components.backend,
        key_provider: components.key_provider,
    })
}

#[cfg(feature = "azure-kv")]
async fn azure_backend() -> Result<BackendComponents> {
    let components = secrets_provider_azure_kv::build_backend()
        .await
        .context("failed to initialize azure secrets backend")?;
    Ok(BackendComponents {
        backend: components.backend,
        key_provider: components.key_provider,
    })
}

#[cfg(feature = "k8s")]
async fn k8s_backend() -> Result<BackendComponents> {
    let components = secrets_provider_k8s::build_backend()
        .await
        .context("failed to initialize kubernetes secrets backend")?;
    Ok(BackendComponents {
        backend: components.backend,
        key_provider: components.key_provider,
    })
}

#[cfg(feature = "vault-kv")]
async fn vault_backend() -> Result<BackendComponents> {
    let components = secrets_provider_vault_kv::build_backend()
        .await
        .context("failed to initialize vault secrets backend")?;
    Ok(BackendComponents {
        backend: components.backend,
        key_provider: components.key_provider,
    })
}
