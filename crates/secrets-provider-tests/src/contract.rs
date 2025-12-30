use anyhow::Result;
use async_trait::async_trait;

/// Minimal contract each provider must satisfy for conformance.
#[async_trait]
pub trait ProviderUnderTest: Send + Sync {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> Result<()>;

    /// Optional listing support.
    async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}
