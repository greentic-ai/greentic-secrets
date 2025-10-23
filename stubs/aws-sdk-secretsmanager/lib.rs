//! In-memory stand-in for the AWS Secrets Manager client.
//!
//! The real SDK exposes an async client with a large surface area. This stub
//! models the handful of calls the Greentic workspace relies upon:
//!
//! * Creating secrets.
//! * Putting new secret versions.
//! * Getting secret payloads.
//! * Enumerating version identifiers.
//!
//! State is kept in-memory and shared across cloned clients, making the stub
//! ideal for deterministic unit tests.
//!
//! # Testing
//! Execute the built-in tests with:
//!
//! ```text
//! cargo test -p aws-sdk-secretsmanager
//! ```

use aws_config::Config;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_VERSION: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct Store {
    secrets: HashMap<String, Vec<SecretEntry>>,
}

#[derive(Clone, Debug)]
struct SecretEntry {
    version_id: String,
    secret_string: Option<String>,
    secret_binary: Option<Vec<u8>>,
    created: SystemTime,
}

/// Client used to interact with the in-memory Secrets Manager.
#[derive(Clone)]
pub struct Client {
    config: Config,
    store: Arc<Mutex<Store>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Client {
    /// Constructs a new client using the provided configuration.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            store: Arc::new(Mutex::new(Store::default())),
        }
    }

    /// Returns the configuration associated with the client.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Creates a new secret unless it already exists.
    pub fn create_secret(&self, input: CreateSecretInput) -> Result<CreateSecretOutput, Error> {
        if input.name.trim().is_empty() {
            return Err(Error::InvalidRequest("secret name may not be empty"));
        }
        if input.secret_string.is_none() && input.secret_binary.is_none() {
            return Err(Error::InvalidRequest(
                "secret must include string or binary payload",
            ));
        }

        let mut guard = self.store.lock().unwrap();
        if guard.secrets.contains_key(&input.name) {
            return Err(Error::ResourceExists(input.name));
        }

        let entry = SecretEntry {
            version_id: next_version_id(),
            secret_string: input.secret_string.clone(),
            secret_binary: input.secret_binary.clone(),
            created: SystemTime::now(),
        };

        guard
            .secrets
            .insert(input.name.clone(), vec![entry.clone()]);
        Ok(CreateSecretOutput {
            arn: format!(
                "arn:aws:secretsmanager:local:000000000000:secret:{}",
                input.name
            ),
            name: input.name,
            version_id: entry.version_id,
        })
    }

    /// Adds a new version to an existing secret.
    pub fn put_secret_value(
        &self,
        input: PutSecretValueInput,
    ) -> Result<PutSecretValueOutput, Error> {
        if input.secret_id.trim().is_empty() {
            return Err(Error::InvalidRequest("secret id may not be empty"));
        }

        if input.secret_string.is_none() && input.secret_binary.is_none() {
            return Err(Error::InvalidRequest(
                "secret must include string or binary payload",
            ));
        }

        let mut guard = self.store.lock().unwrap();
        let entry = guard
            .secrets
            .get_mut(&input.secret_id)
            .ok_or_else(|| Error::ResourceNotFound(input.secret_id.clone()))?;

        let version_id = next_version_id();
        entry.push(SecretEntry {
            version_id: version_id.clone(),
            secret_string: input.secret_string.clone(),
            secret_binary: input.secret_binary.clone(),
            created: SystemTime::now(),
        });

        Ok(PutSecretValueOutput { version_id })
    }

    /// Retrieves a secret value, defaulting to the latest version.
    pub fn get_secret_value(
        &self,
        input: GetSecretValueInput,
    ) -> Result<GetSecretValueOutput, Error> {
        if input.secret_id.trim().is_empty() {
            return Err(Error::InvalidRequest("secret id may not be empty"));
        }

        let guard = self.store.lock().unwrap();
        let versions = guard
            .secrets
            .get(&input.secret_id)
            .ok_or_else(|| Error::ResourceNotFound(input.secret_id.clone()))?;

        let entry = match input.version_id {
            Some(ref version_id) => versions
                .iter()
                .find(|e| &e.version_id == version_id)
                .ok_or_else(|| Error::ResourceNotFound(version_id.clone()))?,
            None => versions
                .last()
                .ok_or_else(|| Error::ResourceNotFound(input.secret_id.clone()))?,
        };

        Ok(GetSecretValueOutput {
            arn: format!(
                "arn:aws:secretsmanager:local:000000000000:secret:{}",
                input.secret_id
            ),
            name: input.secret_id,
            version_id: entry.version_id.clone(),
            secret_string: entry.secret_string.clone(),
            secret_binary: entry.secret_binary.clone(),
        })
    }

    /// Lists the version identifiers that have been created for a secret.
    pub fn list_secret_version_ids(
        &self,
        input: ListSecretVersionIdsInput,
    ) -> Result<ListSecretVersionIdsOutput, Error> {
        if input.secret_id.trim().is_empty() {
            return Err(Error::InvalidRequest("secret id may not be empty"));
        }

        let guard = self.store.lock().unwrap();
        let versions = guard
            .secrets
            .get(&input.secret_id)
            .ok_or_else(|| Error::ResourceNotFound(input.secret_id.clone()))?;

        let version_ids = versions
            .iter()
            .map(|entry| SecretVersionInfo {
                version_id: entry.version_id.clone(),
                created_date: entry.created.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            })
            .collect();

        Ok(ListSecretVersionIdsOutput { version_ids })
    }
}

fn next_version_id() -> String {
    let id = NEXT_VERSION.fetch_add(1, Ordering::Relaxed);
    format!("stub-version-{}", id)
}

/// Error returned by the stub client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Provided request was invalid.
    InvalidRequest(&'static str),
    /// Attempted to create a resource that already exists.
    ResourceExists(String),
    /// Requested resource was not found.
    ResourceNotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidRequest(message) => write!(f, "invalid request: {}", message),
            Error::ResourceExists(name) => write!(f, "resource already exists: {}", name),
            Error::ResourceNotFound(name) => write!(f, "resource not found: {}", name),
        }
    }
}

impl std::error::Error for Error {}

/// Request payload for [`Client::create_secret`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateSecretInput {
    pub name: String,
    pub secret_string: Option<String>,
    pub secret_binary: Option<Vec<u8>>,
}

/// Response payload for [`Client::create_secret`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSecretOutput {
    pub arn: String,
    pub name: String,
    pub version_id: String,
}

/// Request payload for [`Client::put_secret_value`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PutSecretValueInput {
    pub secret_id: String,
    pub secret_string: Option<String>,
    pub secret_binary: Option<Vec<u8>>,
}

/// Response payload for [`Client::put_secret_value`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PutSecretValueOutput {
    pub version_id: String,
}

/// Request payload for [`Client::get_secret_value`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetSecretValueInput {
    pub secret_id: String,
    pub version_id: Option<String>,
}

/// Response payload for [`Client::get_secret_value`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetSecretValueOutput {
    pub arn: String,
    pub name: String,
    pub version_id: String,
    pub secret_string: Option<String>,
    pub secret_binary: Option<Vec<u8>>,
}

/// Request payload for [`Client::list_secret_version_ids`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListSecretVersionIdsInput {
    pub secret_id: String,
}

/// Response payload for [`Client::list_secret_version_ids`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListSecretVersionIdsOutput {
    pub version_ids: Vec<SecretVersionInfo>,
}

/// Metadata for a secret version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretVersionInfo {
    pub version_id: String,
    pub created_date: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get_secret_roundtrip() {
        let client = Client::default();
        let output = client
            .create_secret(CreateSecretInput {
                name: "example".into(),
                secret_string: Some("payload".into()),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(output.name, "example");
        assert!(output.arn.contains("arn:aws:secretsmanager:local"));

        let retrieved = client
            .get_secret_value(GetSecretValueInput {
                secret_id: "example".into(),
                version_id: Some(output.version_id.clone()),
            })
            .unwrap();

        assert_eq!(retrieved.secret_string, Some("payload".into()));
        assert_eq!(retrieved.version_id, output.version_id);
    }

    #[test]
    fn put_creates_new_version_ids() {
        let client = Client::default();
        client
            .create_secret(CreateSecretInput {
                name: "multi".into(),
                secret_string: Some("v1".into()),
                ..Default::default()
            })
            .unwrap();

        let second = client
            .put_secret_value(PutSecretValueInput {
                secret_id: "multi".into(),
                secret_string: Some("v2".into()),
                ..Default::default()
            })
            .unwrap();

        assert!(second.version_id.starts_with("stub-version-"));

        let list = client
            .list_secret_version_ids(ListSecretVersionIdsInput {
                secret_id: "multi".into(),
            })
            .unwrap();

        assert_eq!(list.version_ids.len(), 2);
        assert_eq!(list.version_ids[1].version_id, second.version_id);
    }

    #[test]
    fn get_latest_version_when_unspecified() {
        let client = Client::default();
        client
            .create_secret(CreateSecretInput {
                name: "latest".into(),
                secret_string: Some("a".into()),
                ..Default::default()
            })
            .unwrap();
        client
            .put_secret_value(PutSecretValueInput {
                secret_id: "latest".into(),
                secret_string: Some("b".into()),
                ..Default::default()
            })
            .unwrap();

        let output = client
            .get_secret_value(GetSecretValueInput {
                secret_id: "latest".into(),
                version_id: None,
            })
            .unwrap();

        assert_eq!(output.secret_string, Some("b".into()));
    }

    #[test]
    fn errors_surface_expected_conditions() {
        let client = Client::default();

        let err = client
            .create_secret(CreateSecretInput {
                name: "".into(),
                secret_string: None,
                secret_binary: None,
            })
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));

        let err = client
            .get_secret_value(GetSecretValueInput {
                secret_id: "missing".into(),
                version_id: None,
            })
            .unwrap_err();
        assert!(matches!(err, Error::ResourceNotFound(name) if name == "missing"));
    }
}
