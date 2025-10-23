//! Simplified AWS Secrets Manager backend implementation.
//!
//! This module provides an implementation of [`SecretsBackend`] and
//! [`KeyProvider`] that mimics the behaviour of AWS Secrets Manager and KMS
//! using in-memory data structures. It honours configuration such as secret
//! prefixes and per-environment KMS aliases, making it suitable for tests and
//! local development when the real services are not available.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::Rng;
use secrets_core::backend::{SecretVersion, SecretsBackend, VersionedSecret};
use secrets_core::errors::{Error as CoreError, Result as CoreResult};
use secrets_core::key_provider::KeyProvider;
use secrets_core::types::{Envelope, SecretListItem, SecretMeta, SecretRecord};
use secrets_core::uri::SecretUri;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const DEFAULT_PREFIX: &str = "greentic";

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the in-memory backend based on environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = AwsProviderConfig::from_env()?;
    let backend = AwsSecretsBackend::new(config.clone());
    let key_provider = AwsKmsKeyProvider::new(config);
    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

/// In-memory backend.
#[derive(Clone)]
pub struct AwsSecretsBackend {
    config: AwsProviderConfig,
    store: Arc<Mutex<HashMap<String, Vec<StoredSecret>>>>,
}

impl AwsSecretsBackend {
    pub(crate) fn new(config: AwsProviderConfig) -> Self {
        Self {
            config,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn key(&self, uri: &SecretUri) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            self.config.secret_prefix,
            uri.scope().env(),
            uri.scope()
                .team()
                .map(|team| format!("{team}-{}", uri.scope().tenant()))
                .unwrap_or_else(|| uri.scope().tenant().to_string()),
            uri.category(),
            uri.name()
        )
    }

    fn matches_scope(name: &str, scope: &secrets_core::types::Scope) -> bool {
        name.contains(scope.env()) && name.contains(scope.tenant())
    }
}

impl SecretsBackend for AwsSecretsBackend {
    fn put(&self, record: SecretRecord) -> CoreResult<SecretVersion> {
        let mut guard = self.store.lock().unwrap();
        let key = self.key(&record.meta.uri);
        let entry = guard.entry(key).or_default();
        let next_version = entry.last().map(|s| s.version + 1).unwrap_or(1);
        let stored = StoredSecret::from_record(&record, false)?.with_version(next_version);
        entry.push(stored);
        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> CoreResult<Option<VersionedSecret>> {
        let guard = self.store.lock().unwrap();
        let entry = match guard.get(&self.key(uri)) {
            Some(v) => v,
            None => return Ok(None),
        };
        let stored = match version {
            Some(ver) => entry.iter().find(|item| item.version == ver).cloned(),
            None => entry.last().cloned(),
        };
        match stored {
            None => Ok(None),
            Some(secret) => {
                if secret.deleted {
                    Ok(None)
                } else {
                    Ok(Some(secret.into_versioned()?))
                }
            }
        }
    }

    fn list(
        &self,
        scope: &secrets_core::types::Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> CoreResult<Vec<SecretListItem>> {
        let guard = self.store.lock().unwrap();
        let mut items = Vec::new();
        for (name, versions) in guard.iter() {
            if !Self::matches_scope(name, scope) {
                continue;
            }
            if let Some(latest) = versions.last() {
                if latest.deleted {
                    continue;
                }
                if let Some(item) = latest.clone().into_list_item()? {
                    if category_prefix
                        .map(|prefix| !item.uri.category().starts_with(prefix))
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    if name_prefix
                        .map(|prefix| !item.uri.name().starts_with(prefix))
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    items.push(item);
                }
            }
        }
        Ok(items)
    }

    fn delete(&self, uri: &SecretUri) -> CoreResult<SecretVersion> {
        let mut guard = self.store.lock().unwrap();
        let entry = guard
            .get_mut(&self.key(uri))
            .ok_or_else(|| CoreError::Storage("secret does not exist".into()))?;
        let next_version = entry.last().map(|s| s.version + 1).unwrap_or(1);
        entry.push(StoredSecret {
            version: next_version,
            deleted: true,
            record: None,
        });
        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> CoreResult<Vec<SecretVersion>> {
        let guard = self.store.lock().unwrap();
        let entry = guard.get(&self.key(uri)).cloned().unwrap_or_default();
        Ok(entry
            .into_iter()
            .map(|stored| SecretVersion {
                version: stored.version,
                deleted: stored.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> CoreResult<bool> {
        let guard = self.store.lock().unwrap();
        Ok(guard
            .get(&self.key(uri))
            .and_then(|versions| versions.last())
            .map(|secret| !secret.deleted)
            .unwrap_or(false))
    }
}

/// In-memory KMS key wrapping provider.
#[derive(Clone)]
pub struct AwsKmsKeyProvider {
    config: AwsProviderConfig,
    kek_store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl AwsKmsKeyProvider {
    pub(crate) fn new(config: AwsProviderConfig) -> Self {
        Self {
            config,
            kek_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_or_create_kek(&self, alias: &str) -> Vec<u8> {
        let mut store = self.kek_store.lock().unwrap();
        store
            .entry(alias.to_string())
            .or_insert_with(|| {
                let mut rng = rand::rng();
                let mut key = [0u8; 32];
                rng.fill(&mut key);
                key.to_vec()
            })
            .clone()
    }
}

impl KeyProvider for AwsKmsKeyProvider {
    fn wrap_dek(&self, scope: &secrets_core::types::Scope, dek: &[u8]) -> CoreResult<Vec<u8>> {
        let alias = self
            .config
            .kms_aliases
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| CoreError::Crypto("missing KMS alias".into()))?;
        let kek = self.get_or_create_kek(alias);
        Ok(xor(&kek, dek))
    }

    fn unwrap_dek(
        &self,
        scope: &secrets_core::types::Scope,
        wrapped: &[u8],
    ) -> CoreResult<Vec<u8>> {
        let alias = self
            .config
            .kms_aliases
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| CoreError::Crypto("missing KMS alias".into()))?;
        let kek = self.get_or_create_kek(alias);
        Ok(xor(&kek, wrapped))
    }
}

fn xor(kek: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ kek[idx % kek.len()])
        .collect()
}

fn decode_bytes(input: &str) -> CoreResult<Vec<u8>> {
    STANDARD
        .decode(input.as_bytes())
        .map_err(|err| CoreError::Storage(err.to_string()))
}

#[derive(Clone, Debug)]
struct AwsProviderConfig {
    secret_prefix: String,
    kms_aliases: AliasMap,
}

impl AwsProviderConfig {
    fn from_env() -> Result<Self> {
        let prefix =
            std::env::var("AWS_SM_SECRET_PREFIX").unwrap_or_else(|_| DEFAULT_PREFIX.to_string());
        Ok(Self {
            secret_prefix: prefix,
            kms_aliases: AliasMap::from_env("AWS_SM_KMS_ALIAS")?,
        })
    }
}

#[derive(Clone, Debug)]
struct AliasMap {
    default: Option<String>,
    per_env: HashMap<String, String>,
    per_tenant: HashMap<(String, String), String>,
}

impl AliasMap {
    fn from_env(prefix: &str) -> Result<Self> {
        let default = std::env::var(prefix).ok();
        let mut per_env = HashMap::new();
        let mut per_tenant = HashMap::new();

        for (key, value) in std::env::vars() {
            if !key.starts_with(prefix) || key == prefix {
                continue;
            }
            let suffix = key.trim_start_matches(prefix).trim_matches('_');
            if suffix.is_empty() {
                continue;
            }
            let tokens: Vec<&str> = suffix.split('_').collect();
            match tokens.as_slice() {
                [env] => {
                    per_env.insert(env.to_lowercase(), value.clone());
                }
                [env, tenant] => {
                    per_tenant.insert((env.to_lowercase(), tenant.to_lowercase()), value.clone());
                }
                _ => {}
            }
        }

        Ok(Self {
            default,
            per_env,
            per_tenant,
        })
    }

    fn resolve(&self, env: &str, tenant: &str) -> Option<&str> {
        self.per_tenant
            .get(&(env.to_lowercase(), tenant.to_lowercase()))
            .or_else(|| self.per_env.get(&env.to_lowercase()))
            .or(self.default.as_ref())
            .map(String::as_str)
    }

    #[cfg(test)]
    fn with_default(alias: impl Into<String>) -> Self {
        Self {
            default: Some(alias.into()),
            per_env: HashMap::new(),
            per_tenant: HashMap::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredSecret {
    version: u64,
    deleted: bool,
    record: Option<StoredRecord>,
}

impl StoredSecret {
    fn from_record(record: &SecretRecord, deleted: bool) -> CoreResult<Self> {
        Ok(Self {
            version: 0,
            deleted,
            record: Some(StoredRecord::from_record(record)?),
        })
    }

    fn with_version(mut self, version: u64) -> Self {
        self.version = version;
        self
    }

    fn into_versioned(self) -> CoreResult<VersionedSecret> {
        if self.deleted {
            return Ok(VersionedSecret {
                version: self.version,
                deleted: true,
                record: None,
            });
        }
        let record = self
            .record
            .ok_or_else(|| CoreError::Storage("missing record".into()))?
            .into_record()?;
        Ok(VersionedSecret {
            version: self.version,
            deleted: false,
            record: Some(record),
        })
    }

    fn into_list_item(self) -> CoreResult<Option<SecretListItem>> {
        if self.deleted {
            return Ok(None);
        }
        let record = self
            .record
            .ok_or_else(|| CoreError::Storage("missing record".into()))?;
        Ok(Some(SecretListItem::from_meta(
            &record.meta,
            Some(self.version.to_string()),
        )))
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredRecord {
    meta: SecretMeta,
    envelope: StoredEnvelope,
    value: String,
}

impl StoredRecord {
    fn from_record(record: &SecretRecord) -> CoreResult<Self> {
        Ok(Self {
            meta: record.meta.clone(),
            envelope: StoredEnvelope::from_envelope(&record.envelope),
            value: STANDARD.encode(&record.value),
        })
    }

    fn into_record(self) -> CoreResult<SecretRecord> {
        Ok(SecretRecord::new(
            self.meta,
            decode_bytes(&self.value)?,
            self.envelope.into_envelope()?,
        ))
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredEnvelope {
    algorithm: String,
    nonce: String,
    hkdf_salt: String,
    wrapped_dek: String,
}

impl StoredEnvelope {
    fn from_envelope(envelope: &Envelope) -> Self {
        Self {
            algorithm: envelope.algorithm.to_string(),
            nonce: STANDARD.encode(&envelope.nonce),
            hkdf_salt: STANDARD.encode(&envelope.hkdf_salt),
            wrapped_dek: STANDARD.encode(&envelope.wrapped_dek),
        }
    }

    fn into_envelope(self) -> CoreResult<Envelope> {
        Ok(Envelope {
            algorithm: self
                .algorithm
                .parse()
                .map_err(|_| CoreError::Storage("invalid algorithm".into()))?,
            nonce: decode_bytes(&self.nonce)?,
            hkdf_salt: decode_bytes(&self.hkdf_salt)?,
            wrapped_dek: decode_bytes(&self.wrapped_dek)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrets_core::types::{ContentType, Scope, Visibility};

    fn build_record() -> SecretRecord {
        let scope = Scope::new("prod", "acme", Some("payments".into())).unwrap();
        let uri = SecretUri::new(scope, "config", "api").unwrap();
        let mut meta = SecretMeta::new(uri, Visibility::Team, ContentType::Json);
        meta.description = Some("payments api key".into());
        let envelope = Envelope {
            algorithm: secrets_core::types::EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![1, 2, 3],
            hkdf_salt: vec![4, 5, 6],
            wrapped_dek: vec![7, 8, 9],
        };
        SecretRecord::new(meta, vec![10, 11, 12], envelope)
    }

    #[test]
    fn put_get_roundtrip() {
        let config = AwsProviderConfig {
            secret_prefix: "test".into(),
            kms_aliases: AliasMap::with_default("alias/test"),
        };
        let backend = AwsSecretsBackend::new(config);
        let record = build_record();
        backend.put(record.clone()).unwrap();
        backend.put(record.clone()).unwrap();
        let latest = backend.get(&record.meta.uri, None).unwrap().unwrap();
        assert_eq!(latest.version, 2);
        let first = backend.get(&record.meta.uri, Some(1)).unwrap().unwrap();
        assert_eq!(first.version, 1);
    }

    #[test]
    fn delete_marks_tombstone() {
        let config = AwsProviderConfig {
            secret_prefix: "test".into(),
            kms_aliases: AliasMap::with_default("alias/test"),
        };
        let backend = AwsSecretsBackend::new(config);
        let record = build_record();
        backend.put(record.clone()).unwrap();
        backend.delete(&record.meta.uri).unwrap();
        assert!(backend.get(&record.meta.uri, None).unwrap().is_none());
        assert!(!backend.exists(&record.meta.uri).unwrap());
    }

    #[test]
    fn kms_wrap_unwrap() {
        let config = AwsProviderConfig {
            secret_prefix: "test".into(),
            kms_aliases: AliasMap::with_default("alias/test"),
        };
        let provider = AwsKmsKeyProvider::new(config);
        let scope = Scope::new("prod", "acme", None).unwrap();
        let dek = vec![1, 2, 3, 4, 5];
        let wrapped = provider.wrap_dek(&scope, &dek).unwrap();
        let unwrapped = provider.unwrap_dek(&scope, &wrapped).unwrap();
        assert_eq!(dek, unwrapped);
    }
}
