use crate::errors::Result;
use crate::types::{Scope, SecretListItem, SecretRecord};
use crate::uri::SecretUri;
use serde::{Deserialize, Serialize};

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "azure")]
pub mod azure;
#[cfg(feature = "env")]
pub mod env;
#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "gcp")]
pub mod gcp;
#[cfg(feature = "k8s")]
pub mod k8s;

/// Version metadata describing a specific revision of a secret.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretVersion {
    pub version: u64,
    pub deleted: bool,
}

impl SecretVersion {
    /// Convenience helper to indicate whether the version represents a tombstone.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }
}

/// Versioned record returned by backends.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionedSecret {
    pub version: u64,
    pub deleted: bool,
    pub record: Option<SecretRecord>,
}

impl VersionedSecret {
    /// Returns a reference to the underlying record when present.
    pub fn record(&self) -> Option<&SecretRecord> {
        self.record.as_ref()
    }
}

/// Storage interface implemented by provider backends.
pub trait SecretsBackend: Send + Sync {
    /// Persist an encrypted record and return the assigned version.
    fn put(&self, record: SecretRecord) -> Result<SecretVersion>;

    /// Retrieve the latest (or specific) version of a secret.
    ///
    /// When `version` is `None`, implementors should return the latest non-deleted
    /// record, or `None` when the secret does not exist or is tombstoned.
    /// When `version` is `Some`, tombstoned revisions should be returned with
    /// `deleted = true` and `record = None`.
    fn get(&self, uri: &SecretUri, version: Option<u64>) -> Result<Option<VersionedSecret>>;

    /// List secrets scoped to the provided scope, optionally filtered by category/name prefixes.
    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> Result<Vec<SecretListItem>>;

    /// Create a tombstone and return the version metadata for the deletion.
    fn delete(&self, uri: &SecretUri) -> Result<SecretVersion>;

    /// Enumerate all versions for a secret ordered from oldest to newest.
    fn versions(&self, uri: &SecretUri) -> Result<Vec<SecretVersion>>;

    /// Check whether the latest revision of the secret exists (i.e. is not tombstoned).
    fn exists(&self, uri: &SecretUri) -> Result<bool>;
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

impl<T> SecretsBackend for std::sync::Arc<T>
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
