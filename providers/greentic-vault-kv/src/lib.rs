//! HashiCorp Vault KV v2 backend using the live Vault HTTP API.
//!
//! Each secret is persisted under a KV v2 mount in a directory structure that
//! mirrors the Greentic scope (`env/tenant/[team]/category/name`). Secret
//! records are serialized to JSON and stored in the `data` field as a base64
//! string. The provider also integrates with Vault Transit to wrap and unwrap
//! data encryption keys.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use greentic_secrets_spec::{
    Envelope, KeyProvider, Scope, SecretListItem, SecretMeta, SecretRecord, SecretUri,
    SecretVersion, SecretsBackend, SecretsError, SecretsResult, VersionedSecret,
};
use reqwest::blocking::{Client, Response};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_KV_MOUNT: &str = "secret";
const DEFAULT_KV_PREFIX: &str = "greentic";
const DEFAULT_TRANSIT_MOUNT: &str = "transit";
const DEFAULT_TRANSIT_KEY: &str = "greentic";
const TEAM_PLACEHOLDER: &str = "_";

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the Vault backend and transit key provider from environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = Arc::new(VaultProviderConfig::from_env()?);
    let client = config.build_http_client()?;

    let backend = VaultSecretsBackend::new(config.clone(), client.clone());
    let key_provider = VaultTransitProvider::new(config, client);
    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
struct VaultSecretsBackend {
    config: Arc<VaultProviderConfig>,
    client: Client,
}

impl VaultSecretsBackend {
    fn new(config: Arc<VaultProviderConfig>, client: Client) -> Self {
        Self { config, client }
    }

    fn request(&self, method: Method, path: &str, body: Option<Value>) -> SecretsResult<Response> {
        self.config.request(&self.client, method, path, body)
    }

    fn kv_data_path(&self, uri: &SecretUri) -> String {
        let team = uri.scope().team().unwrap_or(TEAM_PLACEHOLDER);
        format!(
            "{prefix}/{env}/{tenant}/{team}/{category}/{name}",
            prefix = self.config.kv_prefix,
            env = uri.scope().env(),
            tenant = uri.scope().tenant(),
            team = team,
            category = uri.category(),
            name = uri.name()
        )
    }

    fn kv_api_path(&self, suffix: &str) -> String {
        format!(
            "v1/{mount}/{suffix}",
            mount = self.config.kv_mount.trim_matches('/'),
            suffix = suffix.trim_start_matches('/')
        )
    }

    fn list_keys(&self, prefix: &str) -> SecretsResult<Vec<String>> {
        let path = self.kv_api_path(&format!(
            "metadata/{suffix}",
            suffix = prefix.trim_start_matches('/')
        ));
        let method = Method::from_bytes(b"LIST").expect("LIST method supported");
        let response = self.request(method, &path, None)?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(Vec::new()),
            status if status.is_success() => {
                let body = response.text().unwrap_or_default();
                let list: KeyListResponse = serde_json::from_str(&body).map_err(|err| {
                    SecretsError::Storage(format!(
                        "failed to decode vault key list: {err}; body={body}"
                    ))
                })?;
                Ok(list.data.keys.unwrap_or_default())
            }
            status => {
                let body = response.text().unwrap_or_default();
                Err(SecretsError::Storage(format!(
                    "list keys failed: {status} {body}"
                )))
            }
        }
    }

    fn write_secret(&self, uri: &SecretUri, payload: Option<StoredRecord>) -> SecretsResult<u64> {
        let data_path = self.kv_data_path(uri);
        let path = self.kv_api_path(&format!("data/{data_path}"));
        let mut data_obj = Map::new();
        if let Some(record) = payload {
            let encoded = serde_json::to_vec(&record).map_err(|err| {
                SecretsError::Storage(format!("failed to encode secret payload: {err}"))
            })?;
            data_obj.insert("record".into(), Value::String(STANDARD.encode(encoded)));
        } else {
            data_obj.insert("__greentic_deleted".into(), Value::Bool(true));
        }
        let mut body_obj = Map::new();
        body_obj.insert("data".into(), Value::Object(data_obj));
        let body = Value::Object(body_obj);
        let response = self.request(Method::POST, &path, Some(body))?;
        let status = response.status();
        let body = response.text().unwrap_or_default();
        if !status.is_success() {
            return Err(SecretsError::Storage(format!(
                "write secret failed: {status} {body}"
            )));
        }
        let parsed: KvWriteResponse = serde_json::from_str(&body).map_err(|err| {
            SecretsError::Storage(format!(
                "failed to decode vault write response: {err}; body={body}"
            ))
        })?;
        Ok(parsed.data.metadata.version)
    }

    fn read_secret(
        &self,
        uri: &SecretUri,
        version: Option<u64>,
    ) -> SecretsResult<Option<SecretSnapshot>> {
        let data_path = self.kv_data_path(uri);
        let mut path = self.kv_api_path(&format!("data/{data_path}"));
        if let Some(v) = version {
            path.push_str(&format!("?version={v}"));
        }
        let response = self.request(Method::GET, &path, None)?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => {
                let body = response.text().unwrap_or_default();
                let parsed: KvReadResponse = serde_json::from_str(&body).map_err(|err| {
                    SecretsError::Storage(format!(
                        "failed to decode vault read response: {err}; body={body}"
                    ))
                })?;
                let metadata = parsed.data.metadata;
                let deleted = metadata.destroyed
                    || !metadata.deletion_time.is_empty()
                    || parsed.data.data.greentic_deleted.unwrap_or(false);
                if deleted {
                    return Ok(Some(SecretSnapshot {
                        version: metadata.version,
                        deleted: true,
                        record: None,
                    }));
                }
                let record = parsed
                    .data
                    .data
                    .record
                    .map(|value| decode_stored_record(&value))
                    .transpose()?;
                Ok(Some(SecretSnapshot {
                    version: metadata.version,
                    deleted: false,
                    record,
                }))
            }
            status => {
                let body = response.text().unwrap_or_default();
                Err(SecretsError::Storage(format!(
                    "read secret failed: {status} {body}"
                )))
            }
        }
    }

    fn list_versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersionEntry>> {
        let metadata_path =
            self.kv_api_path(&format!("metadata/{data}", data = self.kv_data_path(uri)));
        let response = self.request(Method::GET, &metadata_path, None)?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(Vec::new()),
            status if status.is_success() => {
                let body = response.text().unwrap_or_default();
                let parsed: KvMetadataResponse = serde_json::from_str(&body).map_err(|err| {
                    SecretsError::Storage(format!(
                        "failed to decode metadata response: {err}; body={body}"
                    ))
                })?;
                let mut entries = Vec::new();
                for (version, _meta) in parsed.data.versions.unwrap_or_default() {
                    let snapshot = self.read_secret(uri, Some(version))?;
                    let deleted = match snapshot {
                        Some(snapshot) => snapshot.deleted,
                        None => true,
                    };
                    entries.push(SecretVersionEntry { version, deleted });
                }
                entries.sort_by_key(|entry| entry.version);
                Ok(entries)
            }
            status => {
                let body = response.text().unwrap_or_default();
                Err(SecretsError::Storage(format!(
                    "metadata lookup failed: {status} {body}"
                )))
            }
        }
    }

    fn list_secrets_for_scope(&self, scope: &Scope) -> SecretsResult<Vec<SecretUri>> {
        let team_segment = scope.team().unwrap_or(TEAM_PLACEHOLDER);
        let base_path = format!(
            "{}/{}/{}/{}",
            self.config.kv_prefix,
            scope.env(),
            scope.tenant(),
            team_segment
        );

        let mut uris = Vec::new();
        for category_key in self.list_keys(&base_path)? {
            let category = category_key.trim_end_matches('/');
            if category.is_empty() {
                continue;
            }
            let names_path = format!("{base_path}/{category}");
            for name_key in self.list_keys(&names_path)? {
                let name = name_key.trim_end_matches('/');
                if name.is_empty() {
                    continue;
                }
                let scope_clone = Scope::new(
                    scope.env().to_string(),
                    scope.tenant().to_string(),
                    scope.team().map(|v| v.to_string()),
                )?;
                let uri = SecretUri::new(scope_clone, category, name)?;
                uris.push(uri);
            }
        }
        Ok(uris)
    }
}

impl SecretsBackend for VaultSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        let stored = StoredRecord::from_record(&record)?;
        let version = self.write_secret(&record.meta.uri, Some(stored))?;
        Ok(SecretVersion {
            version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> SecretsResult<Option<VersionedSecret>> {
        match self.read_secret(uri, version)? {
            Some(snapshot) => snapshot.into_versioned(),
            None => Ok(None),
        }
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
        let mut items = Vec::new();
        for uri in self.list_secrets_for_scope(scope)? {
            if let Some(prefix) = category_prefix {
                if !uri.category().starts_with(prefix) {
                    continue;
                }
            }
            if let Some(prefix) = name_prefix {
                if !uri.name().starts_with(prefix) {
                    continue;
                }
            }
            if let Some(versioned) = self.get(&uri, None)? {
                if let Some(record) = versioned.record() {
                    items.push(SecretListItem::from_meta(
                        &record.meta,
                        Some(versioned.version.to_string()),
                    ));
                }
            }
        }
        Ok(items)
    }

    fn delete(&self, uri: &SecretUri) -> SecretsResult<SecretVersion> {
        if self.get(uri, None)?.is_none() {
            return Err(SecretsError::NotFound {
                entity: uri.to_string(),
            });
        }
        let version = self.write_secret(uri, None)?;
        Ok(SecretVersion {
            version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersion>> {
        Ok(self
            .list_versions(uri)?
            .into_iter()
            .map(|entry| SecretVersion {
                version: entry.version,
                deleted: entry.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> SecretsResult<bool> {
        Ok(self.get(uri, None)?.is_some())
    }
}

#[derive(Clone)]
struct VaultTransitProvider {
    config: Arc<VaultProviderConfig>,
    client: Client,
}

impl VaultTransitProvider {
    fn new(config: Arc<VaultProviderConfig>, client: Client) -> Self {
        Self { config, client }
    }

    fn request_transit(&self, operation: &str, body: Value) -> SecretsResult<Value> {
        let path = format!(
            "v1/{}/{}{}",
            self.config.transit_mount.trim_matches('/'),
            operation,
            self.config.transit_key
        );
        let response = self.request(Method::POST, &path, Some(body))?;
        let status = response.status();
        let body = response.text().unwrap_or_default();
        if !status.is_success() {
            return Err(SecretsError::Backend(format!(
                "vault transit call failed: {status} {body}"
            )));
        }
        serde_json::from_str(&body).map_err(|err| {
            SecretsError::Backend(format!(
                "failed to parse transit response: {err}; body={body}"
            ))
        })
    }

    fn request(&self, method: Method, path: &str, body: Option<Value>) -> SecretsResult<Response> {
        self.config.request(&self.client, method, path, body)
    }
}

impl KeyProvider for VaultTransitProvider {
    fn wrap_dek(&self, _scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let body = json!({"plaintext": STANDARD.encode(dek)});
        let response = self.request_transit("encrypt/", body)?;
        let ciphertext = response
            .get("data")
            .and_then(|data| data.get("ciphertext"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| SecretsError::Backend("encrypt response missing ciphertext".into()))?;
        Ok(ciphertext.as_bytes().to_vec())
    }

    fn unwrap_dek(&self, _scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let ciphertext = std::str::from_utf8(wrapped)
            .map_err(|_| SecretsError::Backend("invalid ciphertext encoding".into()))?;
        let body = json!({"ciphertext": ciphertext});
        let response = self.request_transit("decrypt/", body)?;
        let plaintext = response
            .get("data")
            .and_then(|data| data.get("plaintext"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| SecretsError::Backend("decrypt response missing plaintext".into()))?;
        STANDARD
            .decode(plaintext.as_bytes())
            .map_err(|err| SecretsError::Backend(format!("failed to decode plaintext: {err}")))
    }
}

#[derive(Clone, Debug)]
struct VaultProviderConfig {
    addr: String,
    token: String,
    namespace: Option<String>,
    kv_mount: String,
    kv_prefix: String,
    transit_mount: String,
    transit_key: String,
    timeout: Duration,
    ca_bundle: Option<Vec<u8>>,
    insecure_skip_tls: bool,
}

impl VaultProviderConfig {
    fn from_env() -> Result<Self> {
        let addr = std::env::var("VAULT_ADDR").context("set VAULT_ADDR to the Vault server URL")?;
        let token =
            std::env::var("VAULT_TOKEN").context("set VAULT_TOKEN for Vault authentication")?;
        let namespace = std::env::var("VAULT_NAMESPACE").ok();
        let kv_mount =
            std::env::var("VAULT_KV_MOUNT").unwrap_or_else(|_| DEFAULT_KV_MOUNT.to_string());
        let kv_prefix =
            std::env::var("VAULT_KV_PREFIX").unwrap_or_else(|_| DEFAULT_KV_PREFIX.to_string());
        let transit_mount = std::env::var("VAULT_TRANSIT_MOUNT")
            .unwrap_or_else(|_| DEFAULT_TRANSIT_MOUNT.to_string());
        let transit_key =
            std::env::var("VAULT_TRANSIT_KEY").unwrap_or_else(|_| DEFAULT_TRANSIT_KEY.to_string());
        let timeout = std::env::var("VAULT_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(15));
        let ca_bundle = std::env::var("VAULT_CA_BUNDLE")
            .ok()
            .map(|path| fs::read(path).context("failed to read VAULT_CA_BUNDLE"))
            .transpose()?;
        let insecure_skip_tls = std::env::var("VAULT_INSECURE_SKIP_TLS")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(false);

        Ok(Self {
            addr,
            token,
            namespace,
            kv_mount,
            kv_prefix,
            transit_mount,
            transit_key,
            timeout,
            ca_bundle,
            insecure_skip_tls,
        })
    }

    fn build_http_client(&self) -> Result<Client> {
        let mut builder = Client::builder().timeout(self.timeout);
        if let Some(ca) = self.ca_bundle.as_ref() {
            let cert = reqwest::Certificate::from_pem(ca)
                .or_else(|_| reqwest::Certificate::from_der(ca))
                .context("failed to parse VAULT_CA_BUNDLE")?;
            builder = builder.add_root_certificate(cert);
        }
        if self.insecure_skip_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        builder.build().context("failed to build Vault HTTP client")
    }

    fn request(
        &self,
        client: &Client,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> SecretsResult<Response> {
        let url = format!(
            "{}/{}",
            self.addr.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut builder = client.request(method, url);
        builder = builder.header("X-Vault-Token", &self.token);
        if let Some(namespace) = &self.namespace {
            builder = builder.header("X-Vault-Namespace", namespace);
        }
        if let Some(payload) = body {
            builder = builder.json(&payload);
        }
        builder
            .send()
            .map_err(|err| SecretsError::Backend(format!("vault request failed: {err}")))
    }
}

#[derive(Deserialize)]
struct KeyListResponse {
    data: KeyListData,
}

#[derive(Deserialize)]
struct KeyListData {
    keys: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct KvWriteResponse {
    data: WriteMetadataWrapper,
}

#[derive(Deserialize)]
struct WriteMetadataWrapper {
    metadata: VersionMetadata,
}

#[derive(Deserialize)]
struct VersionMetadata {
    version: u64,
    #[serde(default)]
    destroyed: bool,
    #[serde(default)]
    deletion_time: String,
}

#[derive(Deserialize)]
struct KvReadResponse {
    data: KvDataEnvelope,
}

#[derive(Deserialize)]
struct KvDataEnvelope {
    data: KvRecordData,
    metadata: VersionMetadata,
}

#[derive(Deserialize)]
struct KvRecordData {
    #[serde(default)]
    record: Option<String>,
    #[serde(default, rename = "__greentic_deleted")]
    greentic_deleted: Option<bool>,
}

#[derive(Deserialize)]
struct KvMetadataResponse {
    data: KvMetadataData,
}

#[derive(Deserialize)]
struct KvMetadataData {
    #[serde(default)]
    versions: Option<HashMap<u64, VersionMetadata>>, // serde understands numeric keys
}

struct SecretVersionEntry {
    version: u64,
    deleted: bool,
}

struct SecretSnapshot {
    version: u64,
    deleted: bool,
    record: Option<StoredRecord>,
}

impl SecretSnapshot {
    fn into_versioned(self) -> SecretsResult<Option<VersionedSecret>> {
        if self.deleted {
            return Ok(None);
        }

        let record = self
            .record
            .ok_or_else(|| SecretsError::Storage("missing secret record".into()))?
            .into_record()?;

        Ok(Some(VersionedSecret {
            version: self.version,
            deleted: false,
            record: Some(record),
        }))
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

#[derive(Clone, Serialize, Deserialize, Default)]
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

fn decode_stored_record(encoded: &str) -> SecretsResult<StoredRecord> {
    let bytes = STANDARD
        .decode(encoded.as_bytes())
        .map_err(|err| SecretsError::Storage(format!("failed to decode stored payload: {err}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| SecretsError::Storage(format!("failed to decode stored record: {err}")))
}

fn decode_bytes(input: &str) -> SecretsResult<Vec<u8>> {
    STANDARD
        .decode(input.as_bytes())
        .map_err(|err| SecretsError::Storage(err.to_string()))
}
