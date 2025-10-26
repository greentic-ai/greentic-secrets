use crate::error::Result;
use crate::types::{Scope, SecretListItem, SecretRecord};
use crate::uri::SecretUri;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::sync::Arc;

/// Version metadata describing a specific revision of a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretVersion {
    pub version: u64,
    pub deleted: bool,
}

impl SecretVersion {
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }
}

/// Versioned record returned by backends.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VersionedSecret {
    pub version: u64,
    pub deleted: bool,
    pub record: Option<SecretRecord>,
}

impl VersionedSecret {
    pub fn record(&self) -> Option<&SecretRecord> {
        self.record.as_ref()
    }
}

/// Storage interface implemented by provider backends.
pub trait SecretsBackend: Send + Sync {
    fn put(&self, record: SecretRecord) -> Result<SecretVersion>;
    fn get(&self, uri: &SecretUri, version: Option<u64>) -> Result<Option<VersionedSecret>>;
    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> Result<Vec<SecretListItem>>;
    fn delete(&self, uri: &SecretUri) -> Result<SecretVersion>;
    fn versions(&self, uri: &SecretUri) -> Result<Vec<SecretVersion>>;
    fn exists(&self, uri: &SecretUri) -> Result<bool>;
}

#[cfg(feature = "std")]
impl<T> SecretsBackend for Arc<T>
where
    T: SecretsBackend + ?Sized,
{
    fn put(&self, record: SecretRecord) -> Result<SecretVersion> {
        (**self).put(record)
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> Result<Option<VersionedSecret>> {
        (**self).get(uri, version)
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> Result<Vec<SecretListItem>> {
        (**self).list(scope, category_prefix, name_prefix)
    }

    fn delete(&self, uri: &SecretUri) -> Result<SecretVersion> {
        (**self).delete(uri)
    }

    fn versions(&self, uri: &SecretUri) -> Result<Vec<SecretVersion>> {
        (**self).versions(uri)
    }

    fn exists(&self, uri: &SecretUri) -> Result<bool> {
        (**self).exists(uri)
    }
}

impl<T> SecretsBackend for Box<T>
where
    T: SecretsBackend + ?Sized,
{
    fn put(&self, record: SecretRecord) -> Result<SecretVersion> {
        (**self).put(record)
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> Result<Option<VersionedSecret>> {
        (**self).get(uri, version)
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> Result<Vec<SecretListItem>> {
        (**self).list(scope, category_prefix, name_prefix)
    }

    fn delete(&self, uri: &SecretUri) -> Result<SecretVersion> {
        (**self).delete(uri)
    }

    fn versions(&self, uri: &SecretUri) -> Result<Vec<SecretVersion>> {
        (**self).versions(uri)
    }

    fn exists(&self, uri: &SecretUri) -> Result<bool> {
        (**self).exists(uri)
    }
}
