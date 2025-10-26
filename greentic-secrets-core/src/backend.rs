#[cfg(feature = "use_spec")]
pub use greentic_secrets_spec::backend::{SecretVersion, SecretsBackend, VersionedSecret};

#[cfg(not(feature = "use_spec"))]
mod legacy {
    use crate::errors::Result;
    use crate::types::{Scope, SecretListItem, SecretRecord};
    use crate::uri::SecretUri;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SecretVersion {
        pub version: u64,
        pub deleted: bool,
    }

    impl SecretVersion {
        pub fn is_deleted(&self) -> bool {
            self.deleted
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
}

#[cfg(not(feature = "use_spec"))]
pub use legacy::{SecretVersion, SecretsBackend, VersionedSecret};

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
