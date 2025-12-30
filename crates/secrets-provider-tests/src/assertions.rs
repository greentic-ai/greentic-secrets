use crate::ProviderUnderTest;
use crate::retry_async;
use anyhow::{Context, Result};
use std::time::Duration;

pub async fn assert_get_eq<P: ProviderUnderTest>(
    provider: &P,
    provider_name: &str,
    key: &str,
    expected: &[u8],
) -> Result<()> {
    let got = retry_async(
        || async { provider.get(key).await },
        5,
        Duration::from_millis(100),
    )
    .await
    .with_context(|| format!("get failed for {provider_name}:{key}"))?;
    let Some(actual) = got else {
        anyhow::bail!("expected value for {provider_name}:{key}, got none");
    };
    if actual != expected {
        anyhow::bail!(
            "value mismatch for {provider_name}:{key} ({} vs {})",
            actual.len(),
            expected.len()
        );
    }
    Ok(())
}

pub async fn assert_deleted<P: ProviderUnderTest>(
    provider: &P,
    provider_name: &str,
    key: &str,
) -> Result<()> {
    let got = retry_async(
        || async { provider.get(key).await },
        5,
        Duration::from_millis(150),
    )
    .await
    .with_context(|| format!("delete confirmation failed for {provider_name}:{key}"))?;

    if got.is_some() {
        anyhow::bail!("expected deletion for {provider_name}:{key}");
    }
    Ok(())
}
