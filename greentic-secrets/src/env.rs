use async_trait::async_trait;
use greentic_secrets_api::{Result, SecretError, SecretsManager};

/// Simple secrets manager backed by `std::env` for fast iteration.
pub struct EnvSecretsManager;

#[async_trait]
impl SecretsManager for EnvSecretsManager {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        match std::env::var(path) {
            Ok(value) => Ok(value.into_bytes()),
            Err(_) => Err(SecretError::NotFound(path.to_string())),
        }
    }

    async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        Err(SecretError::Permission("env is read-only".into()))
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        Err(SecretError::Permission("env is read-only".into()))
    }
}
