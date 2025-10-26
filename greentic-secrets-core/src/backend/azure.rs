use crate::spec_compat::{
    Error as CoreError, Result as CoreResult, Scope, SecretListItem, SecretRecord, SecretUri,
    SecretVersion, SecretsBackend, VersionedSecret,
};

/// Azure Key Vault backend placeholder (feature-gated).
#[derive(Debug, Clone, Default)]
pub struct AzureKeyVaultBackend;

impl AzureKeyVaultBackend {
    /// Construct a new placeholder backend.
    pub fn new() -> Self {
        Self
    }
}

impl SecretsBackend for AzureKeyVaultBackend {
    fn put(&self, _record: SecretRecord) -> CoreResult<SecretVersion> {
        Err(CoreError::Storage(
            "azure key vault backend requires runtime integration (feature placeholder)".into(),
        ))
    }

    fn get(&self, _uri: &SecretUri, _version: Option<u64>) -> CoreResult<Option<VersionedSecret>> {
        Ok(None)
    }

    fn list(
        &self,
        _scope: &Scope,
        _category_prefix: Option<&str>,
        _name_prefix: Option<&str>,
    ) -> CoreResult<Vec<SecretListItem>> {
        Ok(Vec::new())
    }

    fn delete(&self, _uri: &SecretUri) -> CoreResult<SecretVersion> {
        Err(CoreError::Storage(
            "azure key vault backend requires runtime integration (feature placeholder)".into(),
        ))
    }

    fn versions(&self, _uri: &SecretUri) -> CoreResult<Vec<SecretVersion>> {
        Ok(Vec::new())
    }

    fn exists(&self, _uri: &SecretUri) -> CoreResult<bool> {
        Ok(false)
    }
}
