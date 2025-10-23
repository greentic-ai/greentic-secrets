//! Simplified HashiCorp Vault KV v2 backend with transit-based key wrapping.
//!
//! This module mirrors the subset of KV and transit APIs exercised by the
//! secrets broker. Secrets are stored in-memory using paths compatible with
//! the real services and envelope metadata is serialized to mimic Vault's
//! payloads. Transit wrapping is simulated using per-alias randomly generated
//! keys to avoid pulling in heavy crypto dependencies.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::{rng, Rng};
use secrets_core::backend::{SecretVersion, SecretsBackend, VersionedSecret};
use secrets_core::errors::{Error as CoreError, Result as CoreResult};
use secrets_core::key_provider::KeyProvider;
use secrets_core::types::{Envelope, SecretListItem, SecretMeta, SecretRecord};
use secrets_core::uri::SecretUri;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::debug;

const DEFAULT_KV_MOUNT: &str = "secret";
const DEFAULT_PREFIX: &str = "greentic";

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the in-memory Vault backend using environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = VaultProviderConfig::from_env()?;
    let backend = VaultSecretsBackend::new(config.clone());
    let key_provider = VaultTransitProvider::new(config);
    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
pub struct VaultSecretsBackend {
    config: VaultProviderConfig,
    store: Arc<Mutex<HashMap<String, Vec<StoredSecret>>>>,
}

impl VaultSecretsBackend {
    pub(crate) fn new(config: VaultProviderConfig) -> Self {
        Self {
            config,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn kv_path(&self, uri: &SecretUri) -> String {
        let team = uri.scope().team().unwrap_or("_");
        format!(
            "{}/data/{}/{}/{}/{}/{}/{}",
            self.config.kv_mount,
            self.config.kv_prefix,
            uri.scope().env(),
            uri.scope().tenant(),
            team,
            uri.category(),
            uri.name()
        )
    }

    fn matches_scope(name: &str, scope: &secrets_core::types::Scope) -> bool {
        name.contains(scope.env()) && name.contains(scope.tenant())
    }
}

impl SecretsBackend for VaultSecretsBackend {
    fn put(&self, record: SecretRecord) -> CoreResult<SecretVersion> {
        let mut guard = self.store.lock().unwrap();
        let path = self.kv_path(&record.meta.uri);
        let entry = guard.entry(path).or_default();
        let next_version = entry.last().map(|s| s.version + 1).unwrap_or(1);
        debug!(
            uri = %record.meta.uri,
            kv_path = entry_path_label(&record.meta.uri, &self.config),
            version = next_version,
            "vault kv storing secret"
        );
        entry.push(StoredSecret::from_record(&record, false)?.with_version(next_version));
        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> CoreResult<Option<VersionedSecret>> {
        let guard = self.store.lock().unwrap();
        let entry = match guard.get(&self.kv_path(uri)) {
            Some(v) => v,
            None => return Ok(None),
        };
        let stored = match version {
            Some(v) => entry.iter().find(|item| item.version == v).cloned(),
            None => entry.last().cloned(),
        };
        Ok(match stored {
            Some(secret) => {
                if secret.deleted {
                    None
                } else {
                    Some(secret.into_versioned()?)
                }
            }
            None => None,
        })
    }

    fn list(
        &self,
        scope: &secrets_core::types::Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> CoreResult<Vec<SecretListItem>> {
        let guard = self.store.lock().unwrap();
        let mut items = Vec::new();
        for (path, versions) in guard.iter() {
            if !Self::matches_scope(path, scope) {
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
            .get_mut(&self.kv_path(uri))
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
        Ok(guard
            .get(&self.kv_path(uri))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|secret| SecretVersion {
                version: secret.version,
                deleted: secret.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> CoreResult<bool> {
        let guard = self.store.lock().unwrap();
        Ok(guard
            .get(&self.kv_path(uri))
            .and_then(|versions| versions.last())
            .map(|secret| !secret.deleted)
            .unwrap_or(false))
    }
}

#[derive(Clone)]
pub struct VaultTransitProvider {
    config: VaultProviderConfig,
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl VaultTransitProvider {
    pub(crate) fn new(config: VaultProviderConfig) -> Self {
        Self {
            config,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_or_create_key(&self, alias: &str) -> Vec<u8> {
        let mut guard = self.store.lock().unwrap();
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

impl KeyProvider for VaultTransitProvider {
    fn wrap_dek(&self, scope: &secrets_core::types::Scope, dek: &[u8]) -> CoreResult<Vec<u8>> {
        let alias = self
            .config
            .transit_keys
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| CoreError::Crypto("missing transit key alias".into()))?;
        let key = self.get_or_create_key(alias);
        Ok(xor(&key, dek))
    }

    fn unwrap_dek(
        &self,
        scope: &secrets_core::types::Scope,
        wrapped: &[u8],
    ) -> CoreResult<Vec<u8>> {
        let alias = self
            .config
            .transit_keys
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| CoreError::Crypto("missing transit key alias".into()))?;
        let key = self.get_or_create_key(alias);
        Ok(xor(&key, wrapped))
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
struct VaultProviderConfig {
    kv_mount: String,
    kv_prefix: String,
    transit_keys: AliasMap,
}

impl VaultProviderConfig {
    fn from_env() -> Result<Self> {
        let kv_mount =
            std::env::var("VAULT_KV_MOUNT").unwrap_or_else(|_| DEFAULT_KV_MOUNT.to_string());
        let kv_prefix =
            std::env::var("VAULT_KV_PREFIX").unwrap_or_else(|_| DEFAULT_PREFIX.to_string());
        Ok(Self {
            kv_mount,
            kv_prefix,
            transit_keys: AliasMap::from_env("VAULT_TRANSIT_KEY")?,
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

fn entry_path_label(uri: &SecretUri, config: &VaultProviderConfig) -> String {
    let team = uri.scope().team().unwrap_or("_");
    format!(
        "{}/{}/{}/{}/{}",
        config.kv_prefix,
        uri.scope().env(),
        uri.scope().tenant(),
        team,
        uri.category()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrets_core::types::{ContentType, Scope, Visibility};

    fn sample_record() -> SecretRecord {
        let scope = Scope::new("prod", "payments", Some("platform".into())).unwrap();
        let uri = SecretUri::new(scope, "config", "api").unwrap();
        let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Json);
        meta.description = Some("vault secret".into());
        let envelope = Envelope {
            algorithm: secrets_core::types::EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![1, 2, 3],
            hkdf_salt: vec![4, 5, 6],
            wrapped_dek: vec![7, 8, 9],
        };
        SecretRecord::new(meta, vec![10, 11, 12], envelope)
    }

    #[test]
    fn alias_resolution_prefers_specific_matches() {
        std::env::set_var("VAULT_TRANSIT_KEY", "transit/default");
        std::env::set_var("VAULT_TRANSIT_KEY_PROD", "transit/prod");
        std::env::set_var("VAULT_TRANSIT_KEY_PROD_PAYMENTS", "transit/prod/payments");
        let aliases = AliasMap::from_env("VAULT_TRANSIT_KEY").unwrap();
        assert_eq!(
            aliases.resolve("prod", "payments").unwrap(),
            "transit/prod/payments"
        );
        assert_eq!(aliases.resolve("prod", "billing").unwrap(), "transit/prod");
        assert_eq!(aliases.resolve("dev", "shared").unwrap(), "transit/default");
    }

    #[test]
    fn kv_path_includes_scope_and_category() {
        let config = VaultProviderConfig {
            kv_mount: "secret".into(),
            kv_prefix: "greentic".into(),
            transit_keys: AliasMap::with_default("transit/default"),
        };
        let backend = VaultSecretsBackend::new(config);
        let record = sample_record();
        let path = backend.kv_path(&record.meta.uri);
        assert!(path.contains("secret/data/greentic/prod/payments/platform/config/api"));
    }

    #[test]
    fn transit_round_trip() {
        let config = VaultProviderConfig {
            kv_mount: "secret".into(),
            kv_prefix: "greentic".into(),
            transit_keys: AliasMap::with_default("transit/default"),
        };
        let provider = VaultTransitProvider::new(config);
        let scope = Scope::new("prod", "payments", None).unwrap();
        let dek = vec![0x55; 32];
        let wrapped = provider.wrap_dek(&scope, &dek).unwrap();
        assert_ne!(wrapped, dek);
        let unwrapped = provider.unwrap_dek(&scope, &wrapped).unwrap();
        assert_eq!(dek, unwrapped);
    }
}
