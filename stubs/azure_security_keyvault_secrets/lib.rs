//! Simplified Azure Key Vault Secrets client.
//!
//! The real SDK performs authenticated HTTP requests against Azure. This stub
//! keeps all state in-memory while still exercising credential acquisition via
//! the companion `azure_identity` stub. It supports the subset of operations
//! required by integration tests: setting, getting, listing, and deleting
//! secrets.
//!
//! # Testing
//! Execute the suite with:
//!
//! ```text
//! cargo test -p azure_security_keyvault_secrets
//! ```

use azure_identity::{Error as CredentialError, TokenCredential, TokenRequestOptions};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NEXT_VERSION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
struct StoredSecret {
    properties: SecretProperties,
    value: String,
}

#[derive(Default)]
struct VaultStore {
    secrets: BTreeMap<String, Vec<StoredSecret>>,
}

/// Errors returned by the stub client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Credentials could not be acquired.
    Authentication(String),
    /// The requested secret (or version) was not found.
    SecretNotFound(String),
    /// Validation failure.
    Validation(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Authentication(reason) => write!(f, "authentication failed: {}", reason),
            Error::SecretNotFound(name) => write!(f, "secret not found: {}", name),
            Error::Validation(message) => write!(f, "invalid request: {}", message),
        }
    }
}

impl std::error::Error for Error {}

/// Metadata describing a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretProperties {
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub tags: BTreeMap<String, String>,
    pub created_on: u64,
}

/// Secret payload alongside metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    pub value: Option<String>,
    pub properties: SecretProperties,
}

/// Client for interacting with the in-memory vault.
#[derive(Clone)]
pub struct SecretClient<C: TokenCredential + Clone> {
    vault_url: String,
    credential: C,
    store: Arc<Mutex<VaultStore>>,
}

impl<C: TokenCredential + Clone> SecretClient<C> {
    /// Creates a new client for the specified vault.
    pub fn new(vault_url: impl Into<String>, credential: C) -> Self {
        Self {
            vault_url: vault_url.into(),
            credential,
            store: Arc::new(Mutex::new(VaultStore::default())),
        }
    }

    fn acquire_token(&self) -> Result<(), Error> {
        let scope = format!("{}/.default", self.vault_url);
        self.credential
            .get_token(TokenRequestOptions {
                scopes: vec![scope],
                lifetime: Duration::from_secs(600),
            })
            .map(|_| ())
            .map_err(|err| match err {
                CredentialError::CredentialUnavailable(reason) => {
                    Error::Authentication(reason.to_string())
                }
            })
    }

    /// Sets (or replaces) a secret value, returning the created version.
    pub fn set_secret(
        &self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Secret, Error> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(Error::Validation("secret name may not be empty"));
        }

        self.acquire_token()?;

        let mut guard = self.store.lock().unwrap();
        let entry = guard.secrets.entry(name.clone()).or_default();
        let version = format!("version-{}", NEXT_VERSION.fetch_add(1, Ordering::Relaxed));
        let created_on = SystemTime::now();
        let secret = StoredSecret {
            properties: SecretProperties {
                name: name.clone(),
                version: version.clone(),
                enabled: true,
                tags: BTreeMap::new(),
                created_on: created_on.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            },
            value: value.into(),
        };
        entry.push(secret.clone());
        Ok(Secret {
            value: Some(secret.value),
            properties: secret.properties,
        })
    }

    /// Retrieves the latest version of a secret.
    pub fn get_secret(&self, name: &str) -> Result<Secret, Error> {
        self.get_secret_version(name, None)
    }

    /// Retrieves a specific version of a secret.
    pub fn get_secret_version(&self, name: &str, version: Option<&str>) -> Result<Secret, Error> {
        if name.trim().is_empty() {
            return Err(Error::Validation("secret name may not be empty"));
        }
        self.acquire_token()?;

        let guard = self.store.lock().unwrap();
        let Some(history) = guard.secrets.get(name) else {
            return Err(Error::SecretNotFound(name.into()));
        };

        let stored = match version {
            Some(version_id) => history
                .iter()
                .find(|secret| secret.properties.version == version_id)
                .ok_or_else(|| Error::SecretNotFound(format!("{}#{}", name, version_id)))?,
            None => history
                .last()
                .ok_or_else(|| Error::SecretNotFound(name.into()))?,
        };

        Ok(Secret {
            value: Some(stored.value.clone()),
            properties: stored.properties.clone(),
        })
    }

    /// Lists metadata for all secrets in the vault.
    pub fn list_properties_of_secrets(&self) -> Result<Vec<SecretProperties>, Error> {
        self.acquire_token()?;
        let guard = self.store.lock().unwrap();
        Ok(guard
            .secrets
            .values()
            .filter_map(|history| history.last().map(|secret| secret.properties.clone()))
            .collect())
    }

    /// Deletes the secret and returns its final version.
    pub fn delete_secret(&self, name: &str) -> Result<SecretProperties, Error> {
        if name.trim().is_empty() {
            return Err(Error::Validation("secret name may not be empty"));
        }
        self.acquire_token()?;

        let mut guard = self.store.lock().unwrap();
        let Some(history) = guard.secrets.remove(name) else {
            return Err(Error::SecretNotFound(name.into()));
        };

        history
            .last()
            .map(|secret| secret.properties.clone())
            .ok_or_else(|| Error::SecretNotFound(name.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_identity::DefaultAzureCredential;

    #[test]
    fn set_get_and_list_roundtrip() {
        let client = SecretClient::new("https://vault.local", DefaultAzureCredential::default());
        client.set_secret("api-key", "value-1").unwrap();
        client.set_secret("api-key", "value-2").unwrap();

        let secret = client.get_secret("api-key").unwrap();
        assert_eq!(secret.value, Some("value-2".into()));

        let list = client.list_properties_of_secrets().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "api-key");
    }

    #[test]
    fn delete_secret_removes_entry() {
        let client = SecretClient::new("https://vault.local", DefaultAzureCredential::default());
        client.set_secret("to-delete", "value").unwrap();
        let props = client.delete_secret("to-delete").unwrap();
        assert_eq!(props.name, "to-delete");

        let err = client.get_secret("to-delete").unwrap_err();
        assert!(matches!(err, Error::SecretNotFound(_)));
    }

    #[test]
    fn empty_name_is_rejected() {
        let client = SecretClient::new("https://vault.local", DefaultAzureCredential::default());
        let err = client.set_secret("", "value").unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }

    #[test]
    fn credential_failures_are_propagated() {
        #[derive(Clone, Debug, Default)]
        struct FailingCredential;

        impl TokenCredential for FailingCredential {
            fn get_token(
                &self,
                _: TokenRequestOptions,
            ) -> Result<azure_identity::AccessToken, azure_identity::Error> {
                Err(azure_identity::Error::CredentialUnavailable(
                    "forced failure",
                ))
            }
        }

        let client = SecretClient::new("https://vault.local", FailingCredential);
        let err = client.set_secret("key", "value").unwrap_err();
        assert!(matches!(err, Error::Authentication(reason) if reason == "forced failure"));
    }
}
