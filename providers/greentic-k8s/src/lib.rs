//! Simplified Kubernetes Secrets backend.
//!
//! This module mimics the broker integration points for Kubernetes by mapping
//! each logical secret to a namespace derived from `{env,tenant}` and encoding
//! `{team,category,name,version}` into the Secret resource name. It keeps the
//! state in-process to remain suitable for tests while still exercising the
//! namespace/name mapping logic.

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
use tracing::debug;

#[cfg(feature = "sealedsecrets")]
use tracing::info;

const DEFAULT_NAMESPACE_PREFIX: &str = "greentic";
const DEFAULT_MAX_SECRET_SIZE: usize = 1_048_576; // 1 MiB
const NAMESPACE_MAX_LEN: usize = 63;
const SECRET_NAME_MAX_LEN: usize = 253;

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the backend and key provider from environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = K8sProviderConfig::from_env()?;
    #[cfg(feature = "sealedsecrets")]
    if config.use_sealed_secrets {
        info!("k8s provider configured to emit SealedSecret manifests");
    }

    let backend = K8sSecretsBackend::new(config.clone());
    let key_provider = K8sKeyProvider::new(config);
    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
pub struct K8sSecretsBackend {
    config: K8sProviderConfig,
    store: Arc<Mutex<HashMap<String, Vec<StoredSecret>>>>,
}

impl K8sSecretsBackend {
    pub(crate) fn new(config: K8sProviderConfig) -> Self {
        Self {
            config,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn storage_key(&self, uri: &SecretUri) -> String {
        format!(
            "{}|{}",
            namespace_for_scope(&self.config, uri.scope()),
            canonical_storage_key(uri)
        )
    }

    fn namespace(&self, scope: &Scope) -> String {
        namespace_for_scope(&self.config, scope)
    }
}

impl SecretsBackend for K8sSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        if record.value.len() > self.config.max_secret_size {
            return Err(SecretsError::Storage(format!(
                "secret payload exceeds configured Kubernetes limit of {} bytes",
                self.config.max_secret_size
            )));
        }

        let mut guard = self.store.lock().unwrap();
        let key = self.storage_key(&record.meta.uri);
        let entry = guard.entry(key).or_default();
        let next_version = entry.last().map(|s| s.version + 1).unwrap_or(1);
        let namespace = self.namespace(record.meta.uri.scope());
        let resource_name = secret_resource_name(&record.meta.uri, next_version);
        let resource_kind = if self.config.use_sealed_secrets {
            "SealedSecret"
        } else {
            "Secret"
        };
        debug!(
            namespace = %namespace,
            resource = %resource_name,
            kind = resource_kind,
            version = next_version,
            uri = %record.meta.uri,
            "persisting kubernetes secret"
        );
        entry.push(
            StoredSecret::from_record(&record, false, Some(resource_name))?
                .with_version(next_version),
        );
        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> SecretsResult<Option<VersionedSecret>> {
        let guard = self.store.lock().unwrap();
        let entry = match guard.get(&self.storage_key(uri)) {
            Some(v) => v,
            None => return Ok(None),
        };
        let stored = match version {
            Some(v) => entry.iter().find(|item| item.version == v).cloned(),
            None => entry.last().cloned(),
        };
        Ok(match stored {
            Some(secret) => Some(secret.into_versioned()?),
            None => None,
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
        for versions in guard.values() {
            if let Some(latest) = versions.last() {
                if latest.deleted {
                    continue;
                }
                let Some(stored_record) = latest.record.as_ref() else {
                    continue;
                };
                let meta_scope = stored_record.meta.scope();
                if meta_scope.env() != scope.env() || meta_scope.tenant() != scope.tenant() {
                    continue;
                }
                if let Some(prefix) = category_prefix {
                    if !stored_record.meta.uri.category().starts_with(prefix) {
                        continue;
                    }
                }
                if let Some(prefix) = name_prefix {
                    if !stored_record.meta.uri.name().starts_with(prefix) {
                        continue;
                    }
                }
                if let Some(item) = latest.clone().into_list_item()? {
                    items.push(item);
                }
            }
        }
        Ok(items)
    }

    fn delete(&self, uri: &SecretUri) -> SecretsResult<SecretVersion> {
        let mut guard = self.store.lock().unwrap();
        let entry = guard
            .get_mut(&self.storage_key(uri))
            .ok_or_else(|| SecretsError::Storage("secret does not exist".into()))?;
        let next_version = entry.last().map(|s| s.version + 1).unwrap_or(1);
        entry.push(StoredSecret {
            version: next_version,
            deleted: true,
            record: None,
            kube_name: None,
        });
        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersion>> {
        let guard = self.store.lock().unwrap();
        Ok(guard
            .get(&self.storage_key(uri))
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
            .get(&self.storage_key(uri))
            .and_then(|versions| versions.last())
            .map(|secret| !secret.deleted)
            .unwrap_or(false))
    }
}

#[derive(Clone)]
pub struct K8sKeyProvider {
    config: K8sProviderConfig,
    cache: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl K8sKeyProvider {
    pub(crate) fn new(config: K8sProviderConfig) -> Self {
        Self {
            config,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_or_create_key(&self, alias: &str) -> Vec<u8> {
        let mut guard = self.cache.lock().unwrap();
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

impl KeyProvider for K8sKeyProvider {
    fn wrap_dek(&self, scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let alias = self
            .config
            .key_aliases
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| SecretsError::Crypto("missing key material alias".into()))?;
        let key = self.get_or_create_key(alias);
        Ok(xor_bytes(&key, dek))
    }

    fn unwrap_dek(&self, scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let alias = self
            .config
            .key_aliases
            .resolve(scope.env(), scope.tenant())
            .ok_or_else(|| SecretsError::Crypto("missing key material alias".into()))?;
        let key = self.get_or_create_key(alias);
        Ok(xor_bytes(&key, wrapped))
    }
}

fn xor_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ key[idx % key.len()])
        .collect()
}

#[derive(Clone, Debug)]
struct K8sProviderConfig {
    namespace_prefix: String,
    max_secret_size: usize,
    key_aliases: AliasMap,
    use_sealed_secrets: bool,
}

impl K8sProviderConfig {
    fn from_env() -> Result<Self> {
        let prefix = std::env::var("K8S_NAMESPACE_PREFIX")
            .unwrap_or_else(|_| DEFAULT_NAMESPACE_PREFIX.to_string());
        let max_secret_size = std::env::var("K8S_SECRET_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_SECRET_SIZE);
        Ok(Self {
            namespace_prefix: prefix,
            max_secret_size,
            key_aliases: AliasMap::from_env("K8S_KEK_ALIAS")?,
            use_sealed_secrets: cfg!(feature = "sealedsecrets"),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    kube_name: Option<String>,
}

impl StoredSecret {
    fn from_record(
        record: &SecretRecord,
        deleted: bool,
        kube_name: Option<String>,
    ) -> SecretsResult<Self> {
        Ok(Self {
            version: 0,
            deleted,
            record: Some(StoredRecord::from_record(record)?),
            kube_name,
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

fn namespace_for_scope(config: &K8sProviderConfig, scope: &Scope) -> String {
    let mut labels = Vec::new();
    if !config.namespace_prefix.is_empty() {
        labels.push(sanitize_label(&config.namespace_prefix));
    }
    labels.push(sanitize_label(scope.env()));
    labels.push(sanitize_label(scope.tenant()));
    join_labels(&labels, NAMESPACE_MAX_LEN)
}

fn secret_resource_name(uri: &SecretUri, version: u64) -> String {
    let mut labels = Vec::new();
    if let Some(team) = uri.scope().team() {
        labels.push(sanitize_label(team));
    }
    labels.push(sanitize_label(uri.category()));
    labels.push(sanitize_label(uri.name()));
    labels.push(sanitize_label(&format!("v{version:04}")));
    join_labels(&labels, SECRET_NAME_MAX_LEN)
}

fn sanitize_label(value: &str) -> String {
    let mut label = String::new();
    for ch in value.chars() {
        match ch {
            'a'..='z' | '0'..='9' => label.push(ch),
            '-' | '_' | '.' => {
                if !label.ends_with('-') {
                    label.push('-');
                }
            }
            _ => {}
        }
    }
    while label.starts_with('-') {
        label.remove(0);
    }
    while label.ends_with('-') {
        label.pop();
    }
    if label.is_empty() {
        return "default".into();
    }
    label
}

fn join_labels(labels: &[String], max_len: usize) -> String {
    let mut result = String::new();
    for label in labels {
        if label.is_empty() {
            continue;
        }
        if !result.is_empty() {
            result.push('-');
        }
        result.push_str(label);
    }
    if result.is_empty() {
        result.push_str("default");
    }
    if result.len() > max_len {
        result.truncate(max_len);
        while result.ends_with('-') {
            result.pop();
        }
        if result.is_empty() {
            result.push_str("default");
        }
    }
    result
}

fn canonical_storage_key(uri: &SecretUri) -> String {
    format!(
        "{}/{}/{}/{}/{}",
        uri.scope().env(),
        uri.scope().tenant(),
        uri.scope().team().unwrap_or("_"),
        uri.category(),
        uri.name()
    )
}

fn decode_bytes(input: &str) -> SecretsResult<Vec<u8>> {
    STANDARD
        .decode(input.as_bytes())
        .map_err(|err| SecretsError::Storage(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_spec::{ContentType, EncryptionAlgorithm, Visibility};

    fn sample_record() -> SecretRecord {
        let scope = Scope::new("prod", "payments", Some("core_team".into())).unwrap();
        let uri = SecretUri::new(scope, "config", "api").unwrap();
        let mut meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Json);
        meta.description = Some("k8s secret".into());
        let envelope = Envelope {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            hkdf_salt: vec![13, 14, 15],
            wrapped_dek: vec![16, 17, 18],
        };
        SecretRecord::new(meta, vec![42; 16], envelope)
    }

    fn config() -> K8sProviderConfig {
        K8sProviderConfig {
            namespace_prefix: "gt".into(),
            max_secret_size: DEFAULT_MAX_SECRET_SIZE,
            key_aliases: AliasMap::with_default("alias/default"),
            use_sealed_secrets: false,
        }
    }

    #[test]
    fn namespace_mapping_includes_env_and_tenant() {
        let cfg = config();
        let scope = Scope::new("prod", "accounts", Some("core".into())).unwrap();
        assert_eq!(namespace_for_scope(&cfg, &scope), "gt-prod-accounts");
    }

    #[test]
    fn secret_name_encodes_team_and_version() {
        let record = sample_record();
        let name = secret_resource_name(&record.meta.uri, 3);
        assert_eq!(name, "core-team-config-api-v0003");
    }

    #[test]
    fn rejects_oversized_payloads() {
        let mut cfg = config();
        cfg.max_secret_size = 8;
        let backend = K8sSecretsBackend::new(cfg);
        let mut record = sample_record();
        record.value = vec![0u8; 16];
        let err = backend.put(record).unwrap_err();
        assert!(matches!(err, SecretsError::Storage(_)));
    }

    #[test]
    fn round_trip_versions() {
        let cfg = config();
        let backend = K8sSecretsBackend::new(cfg.clone());
        let record = sample_record();
        let uri = record.meta.uri.clone();

        let ver1 = backend.put(record.clone()).unwrap();
        assert_eq!(ver1.version, 1);

        let ver2 = backend.put(record.clone()).unwrap();
        assert_eq!(ver2.version, 2);

        let latest = backend.get(&uri, None).unwrap().unwrap();
        assert_eq!(latest.version, 2);
        assert!(latest.record().is_some());

        let first = backend.get(&uri, Some(1)).unwrap().unwrap();
        assert_eq!(first.version, 1);
    }

    #[test]
    fn key_provider_wraps_and_unwraps() {
        let cfg = config();
        let provider = K8sKeyProvider::new(cfg);
        let scope = Scope::new("prod", "payments", None).unwrap();
        let dek = vec![0xAC; 32];
        let wrapped = provider.wrap_dek(&scope, &dek).unwrap();
        assert_ne!(wrapped, dek);
        let recovered = provider.unwrap_dek(&scope, &wrapped).unwrap();
        assert_eq!(recovered, dek);
    }
}
