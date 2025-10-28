//! Simplified Azure Key Vault Secrets backend.
//!
//! This in-memory implementation mirrors the APIs required by the broker while
//! avoiding external Azure dependencies. It stores encrypted records in an
//! internal map and simulates KEK wrap/unwrap behaviour using per-alias keys.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use greentic_secrets_spec::prelude::*;
use greentic_secrets_spec::{
    KeyProvider, Scope, SecretVersion, SecretsBackend, SecretsError, SecretsResult, VersionedSecret,
};
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const DEFAULT_VAULT: &str = "local-vault";
const DEFAULT_PREFIX: &str = "greentic";

pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

pub async fn build_backend() -> Result<BackendComponents> {
    let config = AzureProviderConfig::from_env()?;
    let backend = AzureSecretsBackend::new(config.clone());
    let key_provider = AzureKeyProvider::new(config);
    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
pub struct AzureSecretsBackend {
    config: AzureProviderConfig,
    store: Arc<Mutex<HashMap<String, Vec<StoredSecret>>>>,
}

impl AzureSecretsBackend {
    pub(crate) fn new(config: AzureProviderConfig) -> Self {
        Self {
            config,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn secret_name(&self, uri: &SecretUri) -> String {
        format!(
            "{}/secrets/{}/{}/{}/{}/{}",
            self.config.vault_uri,
            self.config.secret_prefix,
            uri.scope().env(),
            uri.scope().tenant(),
            uri.category(),
            uri.name()
        )
    }

    fn matches_scope(name: &str, scope: &Scope) -> bool {
        name.contains(scope.env()) && name.contains(scope.tenant())
    }
}

impl SecretsBackend for AzureSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        let mut guard = self.store.lock().unwrap();
        let key = self.secret_name(&record.meta.uri);
        let entry = guard.entry(key).or_default();
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
pub struct AzureKeyProvider {
    config: AzureProviderConfig,
    store: Arc<Mutex<HashMap<String, KeyMaterial>>>,
}

impl AzureKeyProvider {
    pub(crate) fn new(config: AzureProviderConfig) -> Self {
        Self {
            config,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_or_create_key(&self, alias: &str) -> SecretsResult<KeyMaterial> {
        let mut guard = self.store.lock().unwrap();
        if let Some(material) = guard.get(alias) {
            return Ok(material.clone());
        }

        let mut generator = OsRng;
        let private = RsaPrivateKey::new(&mut generator, 2048)
            .map_err(|err| SecretsError::Crypto(err.to_string()))?;
        let public = RsaPublicKey::from(&private);
        let material = KeyMaterial { private, public };
        guard.insert(alias.to_string(), material.clone());
        Ok(material)
    }
}

impl KeyProvider for AzureKeyProvider {
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let key_id = self
            .config
            .key_ids
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| SecretsError::Crypto("missing key identifier".into()))?;
        let material = self.get_or_create_key(key_id)?;
        let mut generator = OsRng;
        material
            .public
            .encrypt(&mut generator, Pkcs1v15Encrypt, dek)
            .map_err(|err| SecretsError::Crypto(err.to_string()))
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let key_id = self
            .config
            .key_ids
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| SecretsError::Crypto("missing key identifier".into()))?;
        let material = self.get_or_create_key(key_id)?;
        material
            .private
            .decrypt(Pkcs1v15Encrypt, wrapped)
            .map_err(|err| SecretsError::Crypto(err.to_string()))
    }
}

#[derive(Clone)]
struct KeyMaterial {
    private: RsaPrivateKey,
    public: RsaPublicKey,
}

fn decode_bytes(input: &str) -> SecretsResult<Vec<u8>> {
    STANDARD
        .decode(input.as_bytes())
        .map_err(|err| SecretsError::Storage(err.to_string()))
}

#[derive(Clone, Debug)]
struct AzureProviderConfig {
    vault_uri: String,
    secret_prefix: String,
    key_ids: AliasMap,
}

impl AzureProviderConfig {
    fn from_env() -> Result<Self> {
        let vault = std::env::var("AZURE_KV_VAULT").unwrap_or_else(|_| DEFAULT_VAULT.to_string());
        let prefix =
            std::env::var("AZURE_KV_SECRET_PREFIX").unwrap_or_else(|_| DEFAULT_PREFIX.to_string());
        Ok(Self {
            vault_uri: vault,
            secret_prefix: prefix,
            key_ids: AliasMap::from_env("AZURE_KV_KEY_ID")?,
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
            let components: Vec<&str> = suffix.split('_').collect();
            match components.as_slice() {
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

    fn sample_record() -> SecretRecord {
        let scope = Scope::new("prod", "payments", Some("core".into())).unwrap();
        let uri = SecretUri::new(scope, "config", "api").unwrap();
        let mut meta = SecretMeta::new(uri, Visibility::Team, ContentType::Json);
        meta.description = Some("azure secret".into());
        let envelope = Envelope {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![1, 2, 3],
            hkdf_salt: vec![4, 5, 6],
            wrapped_dek: vec![7, 8, 9],
        };
        SecretRecord::new(meta, vec![10, 11, 12], envelope)
    }

    #[test]
    fn alias_map_resolution() {
        std::env::set_var("AZURE_KV_KEY_ID", "key/default");
        std::env::set_var("AZURE_KV_KEY_ID_PROD", "key/prod");
        std::env::set_var("AZURE_KV_KEY_ID_PROD_PAYMENTS", "key/prod/payments");

        let aliases = AliasMap::from_env("AZURE_KV_KEY_ID").unwrap();
        assert_eq!(
            aliases.resolve("prod", "payments").unwrap(),
            "key/prod/payments"
        );
        assert_eq!(aliases.resolve("prod", "billing").unwrap(), "key/prod");
        assert_eq!(aliases.resolve("dev", "shared").unwrap(), "key/default");
    }

    #[test]
    fn secret_name_mapping() {
        let config = AzureProviderConfig {
            vault_uri: "https://vault.vault.azure.net".into(),
            secret_prefix: "prefix".into(),
            key_ids: AliasMap::with_default("key/default"),
        };
        let backend = AzureSecretsBackend::new(config);
        let record = sample_record();
        backend.put(record.clone()).unwrap();
        let stored = backend.get(&record.meta.uri, None).unwrap().unwrap();
        assert_eq!(stored.version, 1);
    }

    #[test]
    fn rsa_key_provider_roundtrip() {
        let config = AzureProviderConfig {
            vault_uri: "https://vault.vault.azure.net".into(),
            secret_prefix: "prefix".into(),
            key_ids: AliasMap::with_default("key/default"),
        };
        let provider = AzureKeyProvider::new(config);
        let scope = Scope::new("prod", "payments", None).unwrap();
        let dek = vec![0xAA; 32];
        let wrapped = provider.wrap_dek(&scope, &dek).unwrap();
        assert_ne!(wrapped, dek);
        let unwrapped = provider.unwrap_dek(&scope, &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }
}
