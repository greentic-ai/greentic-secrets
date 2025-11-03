//! Azure Key Vault provider backed by the live REST APIs.
//!
//! Secrets are stored as JSON-encoded [`SecretRecord`] values inside Key Vault
//! secrets, while Data Encryption Keys (DEKs) are wrapped and unwrapped via
//! the configured Key Vault key. Authentication uses the OAuth2 client
//! credentials flow with values supplied through environment variables.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use greentic_secrets_spec::{
    KeyProvider, Scope, SecretListItem, SecretRecord, SecretUri, SecretVersion, SecretsBackend,
    SecretsError, SecretsResult, VersionedSecret,
};
use reqwest::blocking::Client;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SECRETS_API_VERSION: &str = "7.4";
const KEYS_API_VERSION: &str = "7.4";
const TOKEN_SCOPE: &str = "https://vault.azure.net/.default";
const DEFAULT_PREFIX: &str = "greentic";
const TEAM_PLACEHOLDER: &str = "_";
const DEFAULT_TIMEOUT_SECS: u64 = 15;

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the Azure Key Vault backend using environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = Arc::new(AzureProviderConfig::from_env()?);
    let client = Client::builder()
        .timeout(config.http_timeout)
        .build()
        .context("failed to build reqwest client for azure provider")?;
    let auth = Arc::new(AzureAuth::new(&config, client.clone()));

    let backend = AzureSecretsBackend::new(config.clone(), client.clone(), auth.clone());
    let key_provider = AzureKmsKeyProvider::new(config, client, auth);

    Ok(BackendComponents {
        backend: Box::new(backend),
        key_provider: Box::new(key_provider),
    })
}

#[derive(Clone)]
struct AzureProviderConfig {
    vault_uri: String,
    secret_prefix: String,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    key_name: String,
    key_algorithm: String,
    http_timeout: Duration,
}

impl AzureProviderConfig {
    fn from_env() -> Result<Self> {
        let vault_uri = env::var("GREENTIC_AZURE_VAULT_URI")
            .context("set GREENTIC_AZURE_VAULT_URI with your Key Vault URI")?;
        let tenant_id = env::var("AZURE_TENANT_ID")
            .or_else(|_| env::var("GREENTIC_AZURE_TENANT_ID"))
            .context("set AZURE_TENANT_ID (or GREENTIC_AZURE_TENANT_ID) for the OAuth flow")?;
        let client_id = env::var("AZURE_CLIENT_ID")
            .or_else(|_| env::var("GREENTIC_AZURE_CLIENT_ID"))
            .context("set AZURE_CLIENT_ID (or GREENTIC_AZURE_CLIENT_ID)")?;
        let client_secret = env::var("AZURE_CLIENT_SECRET")
            .or_else(|_| env::var("GREENTIC_AZURE_CLIENT_SECRET"))
            .context("set AZURE_CLIENT_SECRET (or GREENTIC_AZURE_CLIENT_SECRET)")?;
        let key_name = env::var("GREENTIC_AZURE_KEY_NAME")
            .context("set GREENTIC_AZURE_KEY_NAME with the Key Vault key to wrap DEKs")?;

        let key_algorithm = env::var("GREENTIC_AZURE_KEY_ALGORITHM")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "RSA-OAEP".to_string());

        let secret_prefix = env::var("GREENTIC_AZURE_SECRET_PREFIX")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_PREFIX.to_string());

        let timeout = env::var("GREENTIC_AZURE_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|secs| {
                if secs == 0 {
                    None
                } else {
                    Some(Duration::from_secs(secs))
                }
            })
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        Ok(Self {
            vault_uri: vault_uri.trim_end_matches('/').to_string(),
            secret_prefix,
            tenant_id,
            client_id,
            client_secret,
            key_name,
            key_algorithm,
            http_timeout: timeout,
        })
    }

    fn secrets_endpoint(&self) -> String {
        format!("{uri}/secrets", uri = self.vault_uri)
    }

    fn keys_endpoint(&self) -> String {
        format!("{uri}/keys", uri = self.vault_uri)
    }
}

#[derive(Clone)]
struct AzureSecretsBackend {
    config: Arc<AzureProviderConfig>,
    client: Client,
    auth: Arc<AzureAuth>,
}

impl AzureSecretsBackend {
    fn new(config: Arc<AzureProviderConfig>, client: Client, auth: Arc<AzureAuth>) -> Self {
        Self {
            config,
            client,
            auth,
        }
    }

    fn secret_name(&self, uri: &SecretUri) -> String {
        let sanitize = |value: &str| {
            value
                .chars()
                .map(|c| match c {
                    '0'..='9' | 'a'..='z' | 'A'..='Z' | '-' => c.to_ascii_lowercase(),
                    _ => '-',
                })
                .collect::<String>()
        };

        let base = format!(
            "{prefix}-{env}-{tenant}-{team}-{category}-{name}",
            prefix = sanitize(&self.config.secret_prefix),
            env = sanitize(uri.scope().env()),
            tenant = sanitize(uri.scope().tenant()),
            team = uri
                .scope()
                .team()
                .map(sanitize)
                .unwrap_or_else(|| TEAM_PLACEHOLDER.to_string()),
            category = sanitize(uri.category()),
            name = sanitize(uri.name()),
        );

        if base.len() <= 110 {
            return base;
        }

        let mut hasher = Sha256::new();
        hasher.update(base.as_bytes());
        let suffix = hex::encode(&hasher.finalize()[..6]);
        let mut truncated = base[..110].to_string();
        truncated.push('-');
        truncated.push_str(&suffix);
        truncated
    }

    fn request(
        &self,
        method: Method,
        url: String,
        body: Option<Value>,
    ) -> SecretsResult<reqwest::blocking::Response> {
        let token = self.auth.bearer_token()?;
        let builder = match method {
            Method::GET => self.client.get(url),
            Method::POST => self.client.post(url),
            Method::PUT => self.client.put(url),
            Method::DELETE => self.client.delete(url),
            other => self.client.request(other, url),
        };

        let builder = builder.header("Authorization", token);
        let builder = if let Some(payload) = body {
            builder.json(&payload)
        } else {
            builder
        };

        builder
            .send()
            .map_err(|err| SecretsError::Storage(format!("azure request failed: {err}")))
    }

    fn set_secret(&self, name: &str, payload: &StoredSecret) -> SecretsResult<()> {
        let url = format!(
            "{}/{}?api-version={}",
            self.config.secrets_endpoint(),
            name,
            SECRETS_API_VERSION
        );
        let encoded = encode_secret(payload)?;
        let body = json!({ "value": STANDARD.encode(encoded) });

        let response = self.request(Method::PUT, url, Some(body))?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().unwrap_or_default();
            return Err(SecretsError::Storage(format!(
                "set secret failed: {status} {text}"
            )));
        }
        Ok(())
    }

    fn get_latest(&self, name: &str) -> SecretsResult<Option<StoredSecret>> {
        let url = format!(
            "{}/{}?api-version={}",
            self.config.secrets_endpoint(),
            name,
            SECRETS_API_VERSION
        );
        let response = self.request(Method::GET, url, None)?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => {
                let body = response.text().unwrap_or_default();
                parse_secret_bundle(&body)
            }
            status => {
                let text = response.text().unwrap_or_default();
                Err(SecretsError::Storage(format!(
                    "get secret failed: {status} {text}"
                )))
            }
        }
    }

    fn get_version(&self, name: &str, version_id: &str) -> SecretsResult<Option<StoredSecret>> {
        let url = format!(
            "{}/{}/{}?api-version={}",
            self.config.secrets_endpoint(),
            name,
            version_id,
            SECRETS_API_VERSION
        );
        let response = self.request(Method::GET, url, None)?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => {
                let body = response.text().unwrap_or_default();
                parse_secret_bundle(&body)
            }
            status => {
                let text = response.text().unwrap_or_default();
                Err(SecretsError::Storage(format!(
                    "get secret version failed: {status} {text}"
                )))
            }
        }
    }

    fn list_version_ids(&self, name: &str) -> SecretsResult<Vec<String>> {
        let mut url = format!(
            "{}/{}/versions?api-version={}",
            self.config.secrets_endpoint(),
            name,
            SECRETS_API_VERSION
        );
        let mut collected = Vec::new();

        loop {
            let response = self.request(Method::GET, url.clone(), None)?;
            match response.status() {
                StatusCode::NOT_FOUND => return Ok(Vec::new()),
                status if status.is_success() => {
                    let body = response.text().unwrap_or_default();
                    let parsed: SecretVersionListResponse =
                        serde_json::from_str(&body).map_err(|err| {
                            SecretsError::Storage(format!(
                                "failed to parse secret versions list: {err}; body={body}"
                            ))
                        })?;

                    if let Some(entries) = parsed.value {
                        for entry in entries {
                            if let Some(id) = extract_version_segment(&entry.id) {
                                collected.push(id.to_string());
                            }
                        }
                    }

                    if let Some(next) = parsed.next_link {
                        url = next;
                        continue;
                    }
                    break;
                }
                status => {
                    let text = response.text().unwrap_or_default();
                    return Err(SecretsError::Storage(format!(
                        "list secret versions failed: {status} {text}"
                    )));
                }
            }
        }

        Ok(collected)
    }

    fn load_all_versions(&self, name: &str) -> SecretsResult<Vec<StoredSecret>> {
        let mut versions = Vec::new();
        let ids = self.list_version_ids(name)?;
        for version_id in ids {
            if let Some(stored) = self.get_version(name, &version_id)? {
                versions.push(stored);
            }
        }
        versions.sort_by_key(|entry| entry.version);
        Ok(versions)
    }
}

impl SecretsBackend for AzureSecretsBackend {
    fn put(&self, record: SecretRecord) -> SecretsResult<SecretVersion> {
        let secret_name = self.secret_name(&record.meta.uri);
        let versions = self.load_all_versions(&secret_name)?;
        let next_version = versions
            .iter()
            .map(|entry| entry.version)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let stored = StoredSecret::live(next_version, record.clone());
        self.set_secret(&secret_name, &stored)?;

        Ok(SecretVersion {
            version: next_version,
            deleted: false,
        })
    }

    fn get(&self, uri: &SecretUri, version: Option<u64>) -> SecretsResult<Option<VersionedSecret>> {
        let name = self.secret_name(uri);
        if let Some(requested) = version {
            let versions = self.load_all_versions(&name)?;
            return Ok(versions
                .into_iter()
                .find(|entry| entry.version == requested && !entry.deleted)
                .and_then(StoredSecret::into_versioned));
        }

        match self.get_latest(&name)? {
            Some(entry) if !entry.deleted => Ok(entry.into_versioned()),
            _ => Ok(None),
        }
    }

    fn list(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> SecretsResult<Vec<SecretListItem>> {
        let mut items = Vec::new();
        let mut url = format!(
            "{}?api-version={}",
            self.config.secrets_endpoint(),
            SECRETS_API_VERSION
        );

        loop {
            let token = self.auth.bearer_token()?;
            let response = self
                .client
                .get(&url)
                .header("Authorization", token)
                .send()
                .map_err(|err| {
                    SecretsError::Storage(format!("list secrets request failed: {err}"))
                })?;

            let status = response.status();
            let body = response.text().unwrap_or_default();
            if !status.is_success() {
                return Err(SecretsError::Storage(format!(
                    "list secrets failed: {status} {body}"
                )));
            }

            let parsed: SecretListResponse = serde_json::from_str(&body).map_err(|err| {
                SecretsError::Storage(format!(
                    "failed to decode list secrets response: {err}; body={body}"
                ))
            })?;

            if let Some(secrets) = parsed.value {
                for entry in secrets {
                    let Some(secret_name) = extract_secret_name(&entry.id) else {
                        continue;
                    };

                    if !secret_name.starts_with(&self.config.secret_prefix) {
                        continue;
                    }

                    if let Some(stored) = self.get_latest(secret_name)? {
                        if stored.deleted {
                            continue;
                        }
                        if let Some(record) = stored.record {
                            if record.meta.scope().env() != scope.env()
                                || record.meta.scope().tenant() != scope.tenant()
                            {
                                continue;
                            }
                            if scope.team().is_some() && record.meta.scope().team() != scope.team()
                            {
                                continue;
                            }
                            if let Some(prefix) = category_prefix {
                                if !record.meta.uri.category().starts_with(prefix) {
                                    continue;
                                }
                            }
                            if let Some(prefix) = name_prefix {
                                if !record.meta.uri.name().starts_with(prefix) {
                                    continue;
                                }
                            }
                            items.push(SecretListItem::from_meta(
                                &record.meta,
                                Some(stored.version.to_string()),
                            ));
                        }
                    }
                }
            }

            if let Some(next) = parsed.next_link {
                url = next;
                continue;
            }
            break;
        }

        Ok(items)
    }

    fn delete(&self, uri: &SecretUri) -> SecretsResult<SecretVersion> {
        let name = self.secret_name(uri);
        let versions = self.load_all_versions(&name)?;
        if versions.is_empty() {
            return Err(SecretsError::NotFound {
                entity: uri.to_string(),
            });
        }

        let next_version = versions
            .iter()
            .map(|entry| entry.version)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let tombstone = StoredSecret::tombstone(next_version);
        self.set_secret(&name, &tombstone)?;

        Ok(SecretVersion {
            version: next_version,
            deleted: true,
        })
    }

    fn versions(&self, uri: &SecretUri) -> SecretsResult<Vec<SecretVersion>> {
        let name = self.secret_name(uri);
        Ok(self
            .load_all_versions(&name)?
            .into_iter()
            .map(|entry| SecretVersion {
                version: entry.version,
                deleted: entry.deleted,
            })
            .collect())
    }

    fn exists(&self, uri: &SecretUri) -> SecretsResult<bool> {
        Ok(self
            .get_latest(&self.secret_name(uri))?
            .is_some_and(|entry| !entry.deleted))
    }
}

struct AzureAuth {
    token_url: String,
    client_id: String,
    client_secret: String,
    client: Client,
    cache: Mutex<Option<TokenCache>>,
}

impl AzureAuth {
    fn new(config: &AzureProviderConfig, client: Client) -> Self {
        Self {
            token_url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                config.tenant_id
            ),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            client,
            cache: Mutex::new(None),
        }
    }

    fn bearer_token(&self) -> SecretsResult<String> {
        let mut guard = self.cache.lock().unwrap();
        if let Some(cache) = guard.as_ref() {
            if Instant::now() < cache.expires_at {
                return Ok(format!("Bearer {token}", token = cache.token));
            }
        }

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("scope", TOKEN_SCOPE),
        ];

        let response = self
            .client
            .post(&self.token_url)
            .form(&params)
            .send()
            .map_err(|err| {
                SecretsError::Backend(format!("failed to request azure token: {err}"))
            })?;

        let status = response.status();
        let body = response.text().unwrap_or_default();
        if !status.is_success() {
            return Err(SecretsError::Backend(format!(
                "token request failed: {status} {body}"
            )));
        }

        let parsed: TokenResponse = serde_json::from_str(&body).map_err(|err| {
            SecretsError::Backend(format!(
                "failed to parse token response: {err}; body={body}"
            ))
        })?;

        let expires_in = parsed.expires_in.unwrap_or(3600);
        let cache_entry = TokenCache {
            token: parsed.access_token,
            expires_at: Instant::now() + Duration::from_secs(expires_in.saturating_sub(60)),
        };
        let token_string = format!("Bearer {token}", token = cache_entry.token);
        *guard = Some(cache_entry);
        Ok(token_string)
    }
}

struct TokenCache {
    token: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Clone)]
struct AzureKmsKeyProvider {
    config: Arc<AzureProviderConfig>,
    client: Client,
    auth: Arc<AzureAuth>,
}

impl AzureKmsKeyProvider {
    fn new(config: Arc<AzureProviderConfig>, client: Client, auth: Arc<AzureAuth>) -> Self {
        Self {
            config,
            client,
            auth,
        }
    }

    fn key_operation(&self, operation: &str, body: Value) -> SecretsResult<Value> {
        let url = format!(
            "{}/{}/{}?api-version={}",
            self.config.keys_endpoint(),
            self.config.key_name,
            operation,
            KEYS_API_VERSION
        );

        let response = self
            .client
            .post(url)
            .header("Authorization", self.auth.bearer_token()?)
            .json(&body)
            .send()
            .map_err(|err| SecretsError::Backend(format!("azure key request failed: {err}")))?;

        let status = response.status();
        let body = response.text().unwrap_or_default();
        if !status.is_success() {
            return Err(SecretsError::Backend(format!(
                "key operation failed: {status} {body}"
            )));
        }

        serde_json::from_str(&body).map_err(|err| {
            SecretsError::Backend(format!("failed to parse key response: {err}; body={body}"))
        })
    }
}

impl KeyProvider for AzureKmsKeyProvider {
    fn wrap_dek(&self, _scope: &Scope, dek: &[u8]) -> SecretsResult<Vec<u8>> {
        let payload = json!({
            "alg": self.config.key_algorithm,
            "value": STANDARD.encode(dek),
        });
        let response = self.key_operation("wrapkey", payload)?;
        let wrapped = response
            .get("value")
            .and_then(|value| value.as_str())
            .ok_or_else(|| SecretsError::Backend("wrapkey response missing value".into()))?;
        STANDARD
            .decode(wrapped)
            .map_err(|err| SecretsError::Backend(format!("failed to decode wrapped key: {err}")))
    }

    fn unwrap_dek(&self, _scope: &Scope, wrapped: &[u8]) -> SecretsResult<Vec<u8>> {
        let payload = json!({
            "alg": self.config.key_algorithm,
            "value": STANDARD.encode(wrapped),
        });
        let response = self.key_operation("unwrapkey", payload)?;
        let plaintext = response
            .get("value")
            .and_then(|value| value.as_str())
            .ok_or_else(|| SecretsError::Backend("unwrapkey response missing value".into()))?;
        STANDARD
            .decode(plaintext)
            .map_err(|err| SecretsError::Backend(format!("failed to decode unwrapped key: {err}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSecret {
    version: u64,
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<SecretRecord>,
}

impl StoredSecret {
    fn live(version: u64, record: SecretRecord) -> Self {
        Self {
            version,
            deleted: false,
            record: Some(record),
        }
    }

    fn tombstone(version: u64) -> Self {
        Self {
            version,
            deleted: true,
            record: None,
        }
    }

    fn into_versioned(self) -> Option<VersionedSecret> {
        self.record.map(|record| VersionedSecret {
            version: self.version,
            deleted: self.deleted,
            record: Some(record),
        })
    }
}

fn encode_secret(payload: &StoredSecret) -> SecretsResult<Vec<u8>> {
    serde_json::to_vec(payload)
        .map_err(|err| SecretsError::Storage(format!("failed to encode secret payload: {err}")))
}

fn parse_secret_bundle(body: &str) -> SecretsResult<Option<StoredSecret>> {
    let bundle: SecretBundle = serde_json::from_str(body).map_err(|err| {
        SecretsError::Storage(format!("failed to parse secret bundle: {err}; body={body}"))
    })?;
    if let Some(value) = bundle.value {
        let decoded = STANDARD.decode(value).map_err(|err| {
            SecretsError::Storage(format!("failed to decode secret value: {err}"))
        })?;
        let stored: StoredSecret = serde_json::from_slice(&decoded).map_err(|err| {
            SecretsError::Storage(format!("failed to decode stored secret: {err}"))
        })?;
        Ok(Some(stored))
    } else {
        Ok(None)
    }
}

#[derive(Deserialize)]
struct SecretBundle {
    value: Option<String>,
}

#[derive(Deserialize)]
struct SecretListResponse {
    #[serde(default)]
    value: Option<Vec<SecretListEntry>>,
    #[serde(rename = "nextLink")]
    #[serde(default)]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct SecretListEntry {
    id: String,
}

#[derive(Deserialize)]
struct SecretVersionListResponse {
    #[serde(default)]
    value: Option<Vec<SecretVersionEntry>>,
    #[serde(rename = "nextLink")]
    #[serde(default)]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct SecretVersionEntry {
    id: String,
}

fn extract_secret_name(id: &str) -> Option<&str> {
    id.split('/').nth_back(0)
}

fn extract_version_segment(id: &str) -> Option<&str> {
    id.split('/').nth_back(0)
}
