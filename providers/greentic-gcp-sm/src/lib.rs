//! Simplified Google Secret Manager backend implementation.
//!
//! This mirrors the interface expected from GCP Secret Manager and Cloud KMS
//! using purely in-memory data structures, enabling feature-gated builds and
//! tests without external dependencies.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use greentic_secrets_spec::prelude::*;
use greentic_secrets_spec::{
    Scope, SecretVersion, SecretsBackend, SecretsError, SecretsResult, VersionedSecret,
};
use greentic_secrets_support::KeyProvider;
use rand::{rng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const DEFAULT_PREFIX: &str = "greentic";

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the in-memory backend using environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = GcpProviderConfig::from_env()?;
    let backend = GcpSecretsBackend::new(config.clone());
    let key_provider = GcpKmsKeyProvider::new(config);
    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
pub struct GcpSecretsBackend {
    config: GcpProviderConfig,
    store: Arc<Mutex<HashMap<String, Vec<StoredSecret>>>>,
}

impl GcpSecretsBackend {
    pub(crate) fn new(config: GcpProviderConfig) -> Self {
        Self {
            config,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn secret_name(&self, uri: &SecretUri) -> String {
        format!(
            "projects/{}/secrets/{}/{}/{}/{}",
            self.config.project,
            self.config.secret_prefix,
            uri.scope().env(),
            uri.scope().tenant(),
            uri.name()
        )
    }

    fn matches_scope(name: &str, scope: &Scope) -> bool {
        name.contains(scope.env()) && name.contains(scope.tenant())
    }
}

impl SecretsBackend for GcpSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        let mut guard = self.store.lock().unwrap();
        let name = self.secret_name(&record.meta.uri);
        let entry = guard.entry(name).or_default();
        let next_version = entry.last().map(|s| s.version + 1).unwrap_or(1);
        entry.push(StoredSecret::from_record(&record, false)?.with_version(next_version));
        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> SecretsResult<Option<VersionedSecret>> {
        let guard = self.store.lock().unwrap();
        let entry = match guard.get(&self.secret_name(uri)) {
            Some(v) => v,
            None => return Ok(None),
        };
        let stored = match version {
            Some(v) => entry.iter().find(|item| item.version == v).cloned(),
            None => entry.last().cloned(),
        };
        Ok(match stored {
            None => None,
            Some(secret) => Some(secret.into_versioned()?),
        })
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
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

    fn delete(&self, uri: &SecretUri) -> SecretsResult<SecretVersion> {
        let mut guard = self.store.lock().unwrap();
        let entry = guard
            .get_mut(&self.secret_name(uri))
            .ok_or_else(|| SecretsError::Storage("secret does not exist".into()))?;
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

    fn versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersion>> {
        let guard = self.store.lock().unwrap();
        Ok(guard
            .get(&self.secret_name(uri))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|secret| SecretVersion {
                version: secret.version,
                deleted: secret.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> SecretsResult<bool> {
        let guard = self.store.lock().unwrap();
        Ok(guard
            .get(&self.secret_name(uri))
            .and_then(|versions| versions.last())
            .map(|secret| !secret.deleted)
            .unwrap_or(false))
    }
}

#[derive(Clone)]
pub struct GcpKmsKeyProvider {
    config: GcpProviderConfig,
    kek_store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl GcpKmsKeyProvider {
    pub(crate) fn new(config: GcpProviderConfig) -> Self {
        Self {
            config,
            kek_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_or_create_kek(&self, alias: &str) -> Vec<u8> {
        let mut guard = self.kek_store.lock().unwrap();
        guard
            .entry(alias.to_string())
            .or_insert_with(|| {
                let mut generator = rng();
                let mut key = [0u8; 32];
                generator.fill(&mut key);
                key.to_vec()
            })
            .clone()
    }
}

impl KeyProvider for GcpKmsKeyProvider {
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let alias = self
            .config
            .kms_keys
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| SecretsError::Crypto("missing KMS key".into()))?;
        let kek = self.get_or_create_kek(alias);
        Ok(xor(&kek, dek))
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let alias = self
            .config
            .kms_keys
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| SecretsError::Crypto("missing KMS key".into()))?;
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

fn decode_bytes(input: &str) -> SecretsResult<Vec<u8>> {
    STANDARD
        .decode(input.as_bytes())
        .map_err(|err| SecretsError::Storage(err.to_string()))
}

#[derive(Clone, Debug)]
struct GcpProviderConfig {
    project: String,
    secret_prefix: String,
    kms_keys: AliasMap,
}

impl GcpProviderConfig {
    fn from_env() -> Result<Self> {
        let project = std::env::var("GCP_SM_PROJECT")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
            .unwrap_or_else(|_| "local-project".into());
        let prefix =
            std::env::var("GCP_SM_SECRET_PREFIX").unwrap_or_else(|_| DEFAULT_PREFIX.to_string());
        Ok(Self {
            project,
            secret_prefix: prefix,
            kms_keys: AliasMap::from_env("GCP_KMS_KEY")?,
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
            let parts: Vec<&str> = suffix.split('_').collect();
            match parts.as_slice() {
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
    fn from_record(record: &SecretRecord, deleted: bool) -> SecretsResult<Self> {
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

    fn into_versioned(self) -> SecretsResult<VersionedSecret> {
        if self.deleted {
            return Ok(VersionedSecret {
                version: self.version,
                deleted: true,
                record: None,
            });
        }
        let record = self
            .record
            .ok_or_else(|| SecretsError::Storage("missing record".into()))?
            .into_record()?;
        Ok(VersionedSecret {
            version: self.version,
            deleted: false,
            record: Some(record),
        })
    }

    fn into_list_item(self) -> SecretsResult<Option<SecretListItem>> {
        if self.deleted {
            return Ok(None);
        }
        let record = self
            .record
            .ok_or_else(|| SecretsError::Storage("missing record".into()))?;
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
    fn from_record(record: &SecretRecord) -> SecretsResult<Self> {
        Ok(Self {
            meta: record.meta.clone(),
            envelope: StoredEnvelope::from_envelope(&record.envelope),
            value: STANDARD.encode(&record.value),
        })
    }

    fn into_record(self) -> SecretsResult<SecretRecord> {
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

    fn into_envelope(self) -> SecretsResult<Envelope> {
        Ok(Envelope {
            algorithm: self
                .algorithm
                .parse()
                .map_err(|_| SecretsError::Storage("invalid algorithm".into()))?,
            nonce: decode_bytes(&self.nonce)?,
            hkdf_salt: decode_bytes(&self.hkdf_salt)?,
            wrapped_dek: decode_bytes(&self.wrapped_dek)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_spec::{ContentType, EncryptionAlgorithm, Scope, Visibility};

    fn build_record() -> SecretRecord {
        let scope = Scope::new("staging", "payments", None).unwrap();
        let uri = SecretUri::new(scope, "config", "service").unwrap();
        let mut meta = SecretMeta::new(uri, Visibility::Tenant, ContentType::Json);
        meta.description = Some("test secret".into());
        let envelope = Envelope {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![1, 2, 3],
            hkdf_salt: vec![4, 5, 6],
            wrapped_dek: vec![7, 8, 9],
        };
        SecretRecord::new(meta, vec![42, 43, 44], envelope)
    }

    #[test]
    fn put_and_list() {
        let config = GcpProviderConfig {
            project: "proj".into(),
            secret_prefix: "prefix".into(),
            kms_keys: AliasMap::with_default(
                "projects/proj/locations/global/keyRings/default/cryptoKeys/app",
            ),
        };
        let backend = GcpSecretsBackend::new(config);

        let record = build_record();
        backend.put(record.clone()).unwrap();
        let list = backend
            .list(record.meta.uri.scope(), Some("config"), Some("service"))
            .unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn kms_roundtrip() {
        let config = GcpProviderConfig {
            project: "proj".into(),
            secret_prefix: "prefix".into(),
            kms_keys: AliasMap::with_default(
                "projects/proj/locations/global/keyRings/default/cryptoKeys/app",
            ),
        };
        let provider = GcpKmsKeyProvider::new(config);
        let scope = Scope::new("staging", "payments", None).unwrap();
        let dek = vec![10, 20, 30, 40];
        let wrapped = provider.wrap_dek(&scope, &dek).unwrap();
        let unwrapped = provider.unwrap_dek(&scope, &wrapped).unwrap();
        assert_eq!(dek, unwrapped);
    }
}
