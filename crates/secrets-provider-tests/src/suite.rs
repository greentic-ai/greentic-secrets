use crate::{
    Capabilities, ProviderUnderTest, TestEnv, assert_deleted, assert_get_eq, medium_payload,
    small_payload,
};
use anyhow::{Context, Result};

/// Runs the shared conformance suite against a provider.
pub struct ConformanceSuite<'a, P: ProviderUnderTest> {
    provider_name: String,
    provider: &'a P,
    caps: Capabilities,
    env: TestEnv,
}

impl<'a, P: ProviderUnderTest> ConformanceSuite<'a, P> {
    pub fn new(provider_name: impl Into<String>, provider: &'a P, caps: Capabilities) -> Self {
        let provider_name = provider_name.into();
        Self {
            env: TestEnv::from_env(&provider_name),
            provider_name,
            provider,
            caps,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let key = self.env.prefix.key("secret");
        let initial = small_payload();
        let updated = medium_payload();

        self.provider
            .put(&key, &initial)
            .await
            .with_context(|| format!("put failed for {}:{key}", self.provider_name))?;

        assert_get_eq(self.provider, &self.provider_name, &key, &initial).await?;

        self.provider
            .put(&key, &updated)
            .await
            .with_context(|| format!("overwrite failed for {}:{key}", self.provider_name))?;
        assert_get_eq(self.provider, &self.provider_name, &key, &updated).await?;

        if self.caps.list {
            let list = self
                .provider
                .list(&self.env.prefix.base())
                .await
                .with_context(|| format!("list failed for {}:{key}", self.provider_name))?;
            if !list.iter().any(|item| item.ends_with(&key)) {
                anyhow::bail!(
                    "list did not return expected key {}:{key}",
                    self.provider_name
                );
            }
        }

        self.provider
            .delete(&key)
            .await
            .with_context(|| format!("delete failed for {}:{key}", self.provider_name))?;

        if self.env.cleanup {
            assert_deleted(self.provider, &self.provider_name, &key).await?;
        }

        Ok(())
    }
}
