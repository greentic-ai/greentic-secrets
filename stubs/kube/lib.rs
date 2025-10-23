//! Focused in-memory implementation of the `kube` crate for testing.
//!
//! This stub only supports the subset of behaviour that Greentic's Kubernetes
//! backend expects: CRUD operations for `Secret` objects in a namespaced store.
//! The API surface mirrors the real crate closely enough to keep integration
//! code readable without pulling in the full dependency tree.
//!
//! # Testing
//! Run `cargo test -p kube` to validate the mocked client behaviour.

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct ClusterState {
    secrets: BTreeMap<(String, String), Secret>,
}

/// Errors produced by the stub client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MissingResource(String),
    Conflict(String),
    Validation(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingResource(name) => write!(f, "resource not found: {}", name),
            Error::Conflict(name) => write!(f, "resource already exists: {}", name),
            Error::Validation(message) => write!(f, "invalid request: {}", message),
        }
    }
}

impl std::error::Error for Error {}

/// Thin wrapper around the in-memory cluster state.
#[derive(Clone, Default)]
pub struct Client {
    state: Arc<Mutex<ClusterState>>,
}

impl Client {
    /// Constructs a new client with empty cluster state.
    pub fn try_default() -> Result<Self, Error> {
        Ok(Self::default())
    }
}

/// Parameters used when creating resources.
#[derive(Debug, Clone, Default)]
pub struct PostParams {
    pub dry_run: bool,
}

/// Parameters used when deleting resources.
#[derive(Debug, Clone, Default)]
pub struct DeleteParams {
    pub dry_run: bool,
}

/// Parameters used when listing resources.
#[derive(Debug, Clone, Default)]
pub struct ListParams {
    pub label_selector: Option<String>,
}

fn metadata_key(meta: &ObjectMeta) -> Result<(String, String), Error> {
    let name = meta
        .name
        .as_ref()
        .ok_or(Error::Validation("metadata.name is required"))?
        .clone();
    let namespace = meta
        .namespace
        .as_ref()
        .ok_or(Error::Validation("metadata.namespace is required"))?
        .clone();
    Ok((namespace, name))
}

fn matches_selector(secret: &Secret, selector: &str) -> bool {
    let Some(ref labels) = secret.metadata.labels else {
        return selector.is_empty();
    };
    selector
        .split(',')
        .filter(|entry| !entry.is_empty())
        .all(|entry| {
            let mut parts = entry.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => labels.get(key) == Some(&value.to_string()),
                _ => false,
            }
        })
}

pub mod api {
    use super::*;

    enum Namespace {
        All,
        Named(String),
    }

    /// Simplified version of `kube::Api` with support for `Secret` objects.
    pub struct Api<T> {
        client: Client,
        namespace: Namespace,
        _marker: PhantomData<T>,
    }

    impl Api<Secret> {
        /// Returns a namespaced API handle.
        pub fn namespaced(client: Client, namespace: &str) -> Self {
            Self {
                client,
                namespace: Namespace::Named(namespace.into()),
                _marker: PhantomData,
            }
        }

        /// Returns an API bound to the `default` namespace.
        pub fn default_namespaced(client: Client) -> Self {
            Self::namespaced(client, "default")
        }

        /// Returns an API spanning all namespaces.
        pub fn all(client: Client) -> Self {
            Self {
                client,
                namespace: Namespace::All,
                _marker: PhantomData,
            }
        }

        fn namespace_matches(&self, namespace: &str) -> bool {
            match &self.namespace {
                Namespace::All => true,
                Namespace::Named(selected) => selected == namespace,
            }
        }

        /// Creates a new secret in the cluster.
        pub fn create(&self, params: &PostParams, secret: &Secret) -> Result<Secret, Error> {
            if params.dry_run {
                return Ok(secret.clone());
            }

            let mut guard = self.client.state.lock().unwrap();
            let state = &mut guard.secrets;
            let key = metadata_key(&secret.metadata)?;

            if state.contains_key(&key) {
                return Err(Error::Conflict(format!("{}/{}", key.0, key.1)));
            }

            if !self.namespace_matches(&key.0) {
                return Err(Error::Validation("API is scoped to a different namespace"));
            }

            state.insert(key.clone(), secret.clone());
            Ok(state.get(&key).cloned().expect("recently inserted"))
        }

        /// Retrieves a secret by name.
        pub fn get(&self, name: &str) -> Result<Secret, Error> {
            let guard = self.client.state.lock().unwrap();
            match &self.namespace {
                Namespace::All => guard
                    .secrets
                    .iter()
                    .find(|((_, stored_name), _)| stored_name == name)
                    .map(|(_, secret)| secret.clone())
                    .ok_or_else(|| Error::MissingResource(name.into())),
                Namespace::Named(ns) => guard
                    .secrets
                    .get(&(ns.clone(), name.into()))
                    .cloned()
                    .ok_or_else(|| Error::MissingResource(format!("{}/{}", ns, name))),
            }
        }

        /// Lists secrets matching the configured namespace.
        pub fn list(&self, params: &ListParams) -> Result<Vec<Secret>, Error> {
            let guard = self.client.state.lock().unwrap();
            let secrets = guard
                .secrets
                .iter()
                .filter(|((namespace, _), _)| match &self.namespace {
                    Namespace::All => true,
                    Namespace::Named(expected) => expected == namespace,
                })
                .map(|(_, secret)| secret.clone())
                .filter(|secret| {
                    if let Some(ref selector) = params.label_selector {
                        matches_selector(secret, selector)
                    } else {
                        true
                    }
                })
                .collect();
            Ok(secrets)
        }

        /// Replaces the secret with the same name.
        pub fn replace(&self, name: &str, secret: &Secret) -> Result<Secret, Error> {
            let mut guard = self.client.state.lock().unwrap();
            let key = metadata_key(&secret.metadata)?;

            if !self.namespace_matches(&key.0) {
                return Err(Error::Validation("API is scoped to a different namespace"));
            }

            if key.1 != name {
                return Err(Error::Validation("secret name mismatch"));
            }

            let entry = guard
                .secrets
                .get_mut(&key)
                .ok_or_else(|| Error::MissingResource(format!("{}/{}", key.0, key.1)))?;
            *entry = secret.clone();
            Ok(entry.clone())
        }

        /// Deletes a secret.
        pub fn delete(&self, name: &str, params: &DeleteParams) -> Result<(), Error> {
            if params.dry_run {
                return Ok(());
            }

            let mut guard = self.client.state.lock().unwrap();
            match &self.namespace {
                Namespace::All => {
                    let key = guard
                        .secrets
                        .keys()
                        .find(|(_, stored_name)| stored_name == name)
                        .cloned()
                        .ok_or_else(|| Error::MissingResource(name.into()))?;
                    guard.secrets.remove(&key);
                }
                Namespace::Named(ns) => {
                    let removed = guard.secrets.remove(&(ns.clone(), name.into()));
                    if removed.is_none() {
                        return Err(Error::MissingResource(format!("{}/{}", ns, name)));
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_secret(name: &str, namespace: &str) -> Secret {
        let mut secret = Secret::default();
        secret.metadata = ObjectMeta::named(name.to_string(), namespace.to_string());
        secret.metadata.insert_label("managed-by", "greentic");
        secret
    }

    #[test]
    fn create_and_get_secret() {
        let client = Client::try_default().unwrap();
        let api = crate::api::Api::<Secret>::namespaced(client.clone(), "default");
        let secret = make_secret("db", "default");
        api.create(&PostParams::default(), &secret).unwrap();

        let retrieved = api.get("db").unwrap();
        assert_eq!(retrieved.metadata.name.as_deref(), Some("db"));
    }

    #[test]
    fn replace_updates_existing_secret() {
        let client = Client::try_default().unwrap();
        let api = crate::api::Api::<Secret>::namespaced(client.clone(), "default");
        let mut secret = make_secret("token", "default");
        api.create(&PostParams::default(), &secret).unwrap();

        secret.insert_string_data("payload", "one");
        secret.bake_string_data();
        api.replace("token", &secret).unwrap();

        let stored = api.get("token").unwrap();
        let value = stored.data.unwrap().get("payload").cloned().unwrap();
        assert_eq!(value, b"one");
    }

    #[test]
    fn delete_removes_secret() {
        let client = Client::try_default().unwrap();
        let api = crate::api::Api::<Secret>::namespaced(client.clone(), "default");
        let secret = make_secret("remove", "default");
        api.create(&PostParams::default(), &secret).unwrap();
        api.delete("remove", &DeleteParams::default()).unwrap();

        let err = api.get("remove").unwrap_err();
        assert!(matches!(err, Error::MissingResource(_)));
    }

    #[test]
    fn list_filters_by_labels() {
        let client = Client::try_default().unwrap();
        let api = crate::api::Api::<Secret>::namespaced(client.clone(), "ns");
        let mut secret_a = make_secret("a", "ns");
        secret_a.metadata.insert_label("team", "payments");
        api.create(&PostParams::default(), &secret_a).unwrap();

        let mut secret_b = make_secret("b", "ns");
        secret_b.metadata.insert_label("team", "ml");
        api.create(&PostParams::default(), &secret_b).unwrap();

        let list = api
            .list(&ListParams {
                label_selector: Some("team=payments".into()),
            })
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].metadata.name.as_deref(), Some("a"));
    }
}
