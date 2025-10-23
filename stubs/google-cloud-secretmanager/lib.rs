//! Minimal Google Secret Manager client for local testing.
//!
//! The stub maintains all data in-memory and focuses on deterministic
//! behaviour. Secrets are identified by their short name (without project
//! prefix) to keep usage lightweight.
//!
//! # Testing
//! Run `cargo test -p google-cloud-secretmanager` to exercise the behaviour.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_VERSION: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct ProjectState {
    secrets: BTreeMap<String, Vec<SecretVersion>>,
}

#[derive(Clone, Debug)]
struct SecretVersion {
    version: String,
    data: Vec<u8>,
    created: u64,
}

/// Errors emitted by the stub client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    SecretExists(String),
    SecretMissing(String),
    VersionMissing(String),
    Validation(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SecretExists(name) => write!(f, "secret already exists: {}", name),
            Error::SecretMissing(name) => write!(f, "secret missing: {}", name),
            Error::VersionMissing(id) => write!(f, "secret version missing: {}", id),
            Error::Validation(message) => write!(f, "invalid request: {}", message),
        }
    }
}

impl std::error::Error for Error {}

/// Response returned when listing secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    pub name: String,
    pub versions: usize,
}

/// Response returned when accessing a secret version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessSecretVersionResponse {
    pub name: String,
    pub data: Vec<u8>,
    pub create_time: u64,
}

/// In-memory Secret Manager client.
#[derive(Clone)]
pub struct SecretManagerClient {
    project_id: String,
    store: Arc<Mutex<ProjectState>>,
}

impl SecretManagerClient {
    /// Creates a client bound to the provided project ID.
    pub fn new(project_id: impl Into<String>) -> Self {
        Self {
            project_id: project_id.into(),
            store: Arc::new(Mutex::new(ProjectState::default())),
        }
    }

    /// Returns the project the client is bound to.
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Creates a new secret with an empty version history.
    pub fn create_secret(&self, name: &str) -> Result<(), Error> {
        if name.trim().is_empty() {
            return Err(Error::Validation("secret name may not be empty"));
        }

        let mut guard = self.store.lock().unwrap();
        if guard.secrets.contains_key(name) {
            return Err(Error::SecretExists(name.into()));
        }
        guard.secrets.insert(name.into(), Vec::new());
        Ok(())
    }

    /// Adds a new secret version using the provided payload.
    pub fn add_secret_version(
        &self,
        name: &str,
        data: impl Into<Vec<u8>>,
    ) -> Result<String, Error> {
        if name.trim().is_empty() {
            return Err(Error::Validation("secret name may not be empty"));
        }

        let mut guard = self.store.lock().unwrap();
        let versions = guard
            .secrets
            .get_mut(name)
            .ok_or_else(|| Error::SecretMissing(name.into()))?;

        let version = format!("{}-{}", name, NEXT_VERSION.fetch_add(1, Ordering::Relaxed));
        versions.push(SecretVersion {
            version: version.clone(),
            data: data.into(),
            created: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });

        Ok(version)
    }

    /// Retrieves a secret payload.
    ///
    /// If `version` is `None`, the latest version is returned.
    pub fn access_secret_version(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<AccessSecretVersionResponse, Error> {
        if name.trim().is_empty() {
            return Err(Error::Validation("secret name may not be empty"));
        }

        let guard = self.store.lock().unwrap();
        let versions = guard
            .secrets
            .get(name)
            .ok_or_else(|| Error::SecretMissing(name.into()))?;

        let secret = match version {
            Some(requested) => versions
                .iter()
                .find(|entry| entry.version == requested)
                .ok_or_else(|| Error::VersionMissing(requested.into()))?,
            None => versions
                .last()
                .ok_or_else(|| Error::SecretMissing(name.into()))?,
        };

        Ok(AccessSecretVersionResponse {
            name: secret.version.clone(),
            data: secret.data.clone(),
            create_time: secret.created,
        })
    }

    /// Lists all secrets available in the project.
    pub fn list_secrets(&self) -> Vec<Secret> {
        let guard = self.store.lock().unwrap();
        guard
            .secrets
            .iter()
            .map(|(name, versions)| Secret {
                name: format!("projects/{}/secrets/{}", self.project_id, name),
                versions: versions.len(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_add_and_access_versions() {
        let client = SecretManagerClient::new("test-project");
        client.create_secret("database_password").unwrap();
        let v1 = client
            .add_secret_version("database_password", b"super-secret")
            .unwrap();
        assert!(v1.starts_with("database_password-"));

        let response = client
            .access_secret_version("database_password", None)
            .unwrap();
        assert_eq!(response.data, b"super-secret");
        assert!(response.create_time > 0);
    }

    #[test]
    fn list_returns_project_scoped_names() {
        let client = SecretManagerClient::new("workspace");
        client.create_secret("one").unwrap();
        client.add_secret_version("one", "payload").unwrap();

        let list = client.list_secrets();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "projects/workspace/secrets/one");
        assert_eq!(list[0].versions, 1);
    }

    #[test]
    fn errors_for_missing_resources() {
        let client = SecretManagerClient::new("noop");
        let err = client.add_secret_version("missing", "v").unwrap_err();
        assert!(matches!(err, Error::SecretMissing(_)));
    }
}
