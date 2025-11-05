//! Azure Key Vault provider backed by the live REST APIs.
//!
//! Secrets are stored as JSON-encoded [`SecretRecord`] values inside Key Vault
//! secrets, while Data Encryption Keys (DEKs) are wrapped and unwrapped via
//! the configured Key Vault key. Authentication uses the OAuth2 client
//! credentials flow with values supplied through environment variables.

mod auth;

use anyhow::{Context, Result, anyhow, bail};
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
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use auth::{AuthError, KvAuthConfig, request_access_token};

const SECRETS_API_VERSION: &str = "7.4";
const KEYS_API_VERSION: &str = "7.4";
const DEFAULT_PREFIX: &str = "greentic";
const TEAM_PLACEHOLDER: &str = "_";
const DEFAULT_TIMEOUT_SECS: u64 = 15;

struct ClientHolder {
    client: &'static Client,
    insecure: bool,
}

static AZURE_HTTP_CLIENT: OnceLock<ClientHolder> = OnceLock::new();

/// Components returned to the broker wiring.
pub struct BackendComponents {
    pub backend: Box<dyn SecretsBackend>,
    pub key_provider: Box<dyn KeyProvider>,
}

/// Construct the Azure Key Vault backend using environment configuration.
pub async fn build_backend() -> Result<BackendComponents> {
    let config = Arc::new(AzureProviderConfig::from_env()?);

    let timeout = config.http_timeout;
    let insecure = config.tls_insecure_skip_verify;
    let config_for_block = config.clone();

    let (client, auth) =
        tokio::task::spawn_blocking(move || -> Result<(Client, Arc<AzureAuth>)> {
            let client_ref = shared_blocking_client(timeout, insecure)?;
            let auth = Arc::new(AzureAuth::new(&config_for_block));
            Ok((client_ref.clone(), auth))
        })
        .await
        .map_err(|err| anyhow!("failed to initialise azure provider: {err}"))??;

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
    key_name: String,
    key_algorithm: String,
    http_timeout: Duration,
    auth_mode: AzureAuthMode,
    tls_insecure_skip_verify: bool,
}

#[derive(Clone)]
enum AzureAuthMode {
    ClientCredentials { config: KvAuthConfig },
    StaticToken { bearer: String },
}

fn uri_uses_loopback_host(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    lower.contains("127.0.0.1")
        || lower.contains("localhost")
        || lower.contains("[::1]")
        || lower.contains("::1")
}

fn shared_blocking_client(timeout: Duration, insecure: bool) -> Result<&'static Client> {
    if let Some(holder) = AZURE_HTTP_CLIENT.get() {
        if holder.insecure == insecure {
            return Ok(holder.client);
        } else {
            bail!(
                "azure http client already initialised with different TLS settings; restart process to change verification mode"
            );
        }
    }

    let builder_timeout = timeout;
    let builder_insecure = insecure;
    let client = thread::spawn(move || {
        Client::builder()
            .timeout(builder_timeout)
            .danger_accept_invalid_certs(builder_insecure)
            .danger_accept_invalid_hostnames(builder_insecure)
            .build()
    })
    .join()
    .map_err(|_| anyhow::anyhow!("azure http client builder thread panicked"))?
    .context("failed to build reqwest client for azure provider")?;

    let leaked = Box::leak(Box::new(client));
    let holder = ClientHolder {
        client: leaked,
        insecure,
    };
    let _ = AZURE_HTTP_CLIENT.set(holder);

    let stored = AZURE_HTTP_CLIENT
        .get()
        .expect("azure http client should be initialised");

    if stored.insecure != insecure {
        bail!(
            "azure http client initialised with different TLS settings; restart process to change verification mode"
        );
    }

    Ok(stored.client)
}

impl AzureProviderConfig {
    fn from_env() -> Result<Self> {
        let vault_uri = env::var("AZURE_KEYVAULT_URL")
            .or_else(|_| env::var("AZURE_KEYVAULT_URI"))
            .or_else(|_| env::var("GREENTIC_AZURE_VAULT_URI"))
            .context(
                "set AZURE_KEYVAULT_URL (or AZURE_KEYVAULT_URI / GREENTIC_AZURE_VAULT_URI) with your Key Vault URL",
            )?;
        let mut static_token = env::var("GREENTIC_AZURE_BEARER_TOKEN")
            .or_else(|_| env::var("AZURE_KEYVAULT_BEARER_TOKEN"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        if static_token.is_none() && uri_uses_loopback_host(&vault_uri) {
            static_token = Some("emulator".to_string());
        }

        let tls_insecure_skip_verify = env::var("AZURE_KEYVAULT_INSECURE_SKIP_VERIFY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or_else(|| uri_uses_loopback_host(&vault_uri));

        let auth_mode = if let Some(token) = static_token {
            AzureAuthMode::StaticToken { bearer: token }
        } else {
            let config = KvAuthConfig::from_env().context(
                "set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET to enable Azure Key Vault authentication",
            )?;
            AzureAuthMode::ClientCredentials { config }
        };

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
            key_name,
            key_algorithm,
            http_timeout: timeout,
            auth_mode,
            tls_insecure_skip_verify,
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

    fn invoke<T, F>(&self, task: F) -> SecretsResult<T>
    where
        T: Send + 'static,
        F: Send
            + 'static
            + FnOnce(Client, Arc<AzureAuth>, Arc<AzureProviderConfig>) -> SecretsResult<T>,
    {
        let client = self.client.clone();
        let auth = self.auth.clone();
        let config = self.config.clone();

        match thread::spawn(move || task(client, auth, config)).join() {
            Ok(result) => result,
            Err(cause) => {
                let message = if let Some(text) = cause.downcast_ref::<&str>() {
                    *text
                } else if let Some(text) = cause.downcast_ref::<String>() {
                    text.as_str()
                } else {
                    "azure worker thread panicked"
                };
                Err(SecretsError::Backend(message.into()))
            }
        }
    }

    fn set_secret(&self, name: &str, payload: &StoredSecret) -> SecretsResult<()> {
        let secret = name.to_owned();
        let stored = payload.clone();
        self.invoke(move |client, auth, config| {
            let url = format!(
                "{}/{}?api-version={}",
                config.secrets_endpoint(),
                secret,
                SECRETS_API_VERSION
            );
            let encoded = encode_secret(&stored)?;
            let body = json!({ "value": STANDARD.encode(encoded) });

            let response = blocking_request(
                &client,
                &auth,
                config.as_ref(),
                Method::PUT,
                url,
                Some(body),
            )?;
            let status = response.status();
            if !status.is_success() {
                let text = response.text().unwrap_or_default();
                return Err(SecretsError::Storage(format!(
                    "set secret failed: {status} {text}"
                )));
            }
            Ok(())
        })
    }

    fn get_latest(&self, name: &str) -> SecretsResult<Option<StoredSecret>> {
        let secret = name.to_owned();
        self.invoke(move |client, auth, config| {
            let url = format!(
                "{}/{}?api-version={}",
                config.secrets_endpoint(),
                secret,
                SECRETS_API_VERSION
            );
            let response =
                blocking_request(&client, &auth, config.as_ref(), Method::GET, url, None)?;
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
        })
    }

    fn get_version(&self, name: &str, version_id: &str) -> SecretsResult<Option<StoredSecret>> {
        let secret = name.to_owned();
        let version = version_id.to_owned();
        self.invoke(move |client, auth, config| {
            let url = format!(
                "{}/{}/{}?api-version={}",
                config.secrets_endpoint(),
                secret,
                version,
                SECRETS_API_VERSION
            );
            let response =
                blocking_request(&client, &auth, config.as_ref(), Method::GET, url, None)?;
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
        })
    }

    fn list_version_ids(&self, name: &str) -> SecretsResult<Vec<String>> {
        let secret = name.to_owned();
        self.invoke(move |client, auth, config| {
            let mut url = format!(
                "{}/{}/versions?api-version={}",
                config.secrets_endpoint(),
                secret,
                SECRETS_API_VERSION
            );
            let mut collected = Vec::new();

            loop {
                let response = blocking_request(
                    &client,
                    &auth,
                    config.as_ref(),
                    Method::GET,
                    url.clone(),
                    None,
                )?;
                match response.status() {
                    StatusCode::NOT_FOUND => return Ok(Vec::new()),
                    status if status.is_success() => {
                        let body = response.text().unwrap_or_default();
                        let parsed: SecretVersionListResponse = serde_json::from_str(&body)
                            .map_err(|err| {
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
        })
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
        let scope = scope.clone();
        let category_prefix = category_prefix.map(|s| s.to_string());
        let name_prefix = name_prefix.map(|s| s.to_string());

        self.invoke(move |client, auth, config| {
            let mut items = Vec::new();
            let mut url = format!(
                "{}?api-version={}",
                config.secrets_endpoint(),
                SECRETS_API_VERSION
            );

            loop {
                let response = blocking_request(
                    &client,
                    &auth,
                    config.as_ref(),
                    Method::GET,
                    url.clone(),
                    None,
                )?;
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

                        if !secret_name.starts_with(&config.secret_prefix) {
                            continue;
                        }

                        if let Some(stored) =
                            blocking_get_latest(&client, &auth, config.as_ref(), secret_name)?
                        {
                            if stored.deleted {
                                continue;
                            }
                            if let Some(record) = stored.record {
                                if record.meta.scope().env() != scope.env()
                                    || record.meta.scope().tenant() != scope.tenant()
                                {
                                    continue;
                                }
                                if scope.team().is_some()
                                    && record.meta.scope().team() != scope.team()
                                {
                                    continue;
                                }
                                if let Some(prefix) = category_prefix.as_deref() {
                                    if !record.meta.uri.category().starts_with(prefix) {
                                        continue;
                                    }
                                }
                                if let Some(prefix) = name_prefix.as_deref() {
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
        })
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
    cache: Mutex<Option<TokenCache>>,
    token_http: reqwest::blocking::Client,
    strategy: AzureAuthStrategy,
}

#[derive(Clone)]
enum AzureAuthStrategy {
    ClientCredentials { config: KvAuthConfig },
    StaticToken { header: String },
}

impl AzureAuth {
    fn new(config: &AzureProviderConfig) -> Self {
        let strategy = match &config.auth_mode {
            AzureAuthMode::ClientCredentials { config } => {
                tracing::info!(
                    "azure credential: ClientSecretCredential (tenant_id={}, scope={})",
                    config.tenant_id,
                    config.scope
                );
                AzureAuthStrategy::ClientCredentials {
                    config: config.clone(),
                }
            }
            AzureAuthMode::StaticToken { bearer } => {
                tracing::info!("azure credential: static bearer token");
                let trimmed = bearer.trim();
                let header = if trimmed.to_ascii_lowercase().starts_with("bearer ") {
                    trimmed.to_string()
                } else {
                    format!("Bearer {trimmed}")
                };
                AzureAuthStrategy::StaticToken { header }
            }
        };

        let token_http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .expect("azure token client build must succeed");

        Self {
            cache: Mutex::new(None),
            token_http,
            strategy,
        }
    }

    fn bearer_token(&self) -> SecretsResult<String> {
        match &self.strategy {
            AzureAuthStrategy::StaticToken { header } => Ok(header.clone()),
            AzureAuthStrategy::ClientCredentials { config } => {
                let mut guard = self.cache.lock().unwrap();
                if let Some(cache) = guard.as_ref() {
                    if Instant::now() < cache.expires_at {
                        return Ok(format!("Bearer {}", cache.token));
                    }
                }

                let token = match request_access_token(&self.token_http, config) {
                    Ok(token) => token,
                    Err(AuthError::Unauthorized { status, body }) => {
                        return Err(SecretsError::Backend(format!(
                            "Azure AAD rejected client credentials ({status}). body={body}"
                        )));
                    }
                    Err(err) => {
                        return Err(SecretsError::Backend(format!(
                            "failed to request azure token: {err}"
                        )));
                    }
                };

                let cache_entry = TokenCache {
                    token: token.token.clone(),
                    expires_at: Instant::now() + token.expires_in,
                };
                let token_string = format!("Bearer {}", cache_entry.token);
                *guard = Some(cache_entry);
                Ok(token_string)
            }
        }
    }

    fn scope_hint(&self) -> Option<&str> {
        match &self.strategy {
            AzureAuthStrategy::ClientCredentials { config } => Some(config.scope.as_str()),
            AzureAuthStrategy::StaticToken { .. } => None,
        }
    }
}

struct TokenCache {
    token: String,
    expires_at: Instant,
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

    fn invoke<T, F>(&self, task: F) -> SecretsResult<T>
    where
        T: Send + 'static,
        F: Send
            + 'static
            + FnOnce(Client, Arc<AzureAuth>, Arc<AzureProviderConfig>) -> SecretsResult<T>,
    {
        let client = self.client.clone();
        let auth = self.auth.clone();
        let config = self.config.clone();

        match thread::spawn(move || task(client, auth, config)).join() {
            Ok(result) => result,
            Err(cause) => {
                let message = if let Some(text) = cause.downcast_ref::<&str>() {
                    *text
                } else if let Some(text) = cause.downcast_ref::<String>() {
                    text.as_str()
                } else {
                    "azure key worker thread panicked"
                };
                Err(SecretsError::Backend(message.into()))
            }
        }
    }

    fn key_operation(&self, operation: &str, body: Value) -> SecretsResult<Value> {
        let operation = operation.to_owned();
        self.invoke(move |client, auth, config| {
            let url = format!(
                "{}/{}/{}?api-version={}",
                config.keys_endpoint(),
                config.key_name,
                operation,
                KEYS_API_VERSION
            );

            let response = blocking_request(
                &client,
                &auth,
                config.as_ref(),
                Method::POST,
                url,
                Some(body),
            )?;
            let status = response.status();
            let payload = response.text().unwrap_or_default();
            if !status.is_success() {
                return Err(SecretsError::Backend(format!(
                    "key operation failed: {status} {payload}"
                )));
            }

            serde_json::from_str(&payload).map_err(|err| {
                SecretsError::Backend(format!(
                    "failed to parse key response: {err}; body={payload}"
                ))
            })
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

fn blocking_request(
    client: &Client,
    auth: &AzureAuth,
    config: &AzureProviderConfig,
    method: Method,
    url: String,
    body: Option<Value>,
) -> SecretsResult<reqwest::blocking::Response> {
    let token = auth.bearer_token()?;
    let builder = match method {
        Method::GET => client.get(url),
        Method::POST => client.post(url),
        Method::PUT => client.put(url),
        Method::DELETE => client.delete(url),
        other => client.request(other, url),
    };

    let builder = builder.header("Authorization", token);
    let builder = if config.tls_insecure_skip_verify {
        builder
            .header("x-ms-keyvault-region", "local")
            .header("x-ms-keyvault-service-version", "1.6.0.0")
    } else {
        builder
    };
    let builder = if let Some(payload) = body {
        builder.json(&payload)
    } else {
        builder
    };

    let response = builder
        .send()
        .map_err(|err| SecretsError::Storage(format!("azure request failed: {err}")))?;

    if response.status() == StatusCode::UNAUTHORIZED {
        let body = response.text().unwrap_or_default();
        let scope_hint = auth.scope_hint().unwrap_or("unknown");
        let mut hint = format!(
            "Azure Key Vault returned 401 Unauthorized. Hint: ensure AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_KEYVAULT_URL are configured. Scope used: {scope_hint}. Key Vault URL: {}.",
            config.vault_uri
        );
        hint.push_str(" Verify credentials with: az account get-access-token --scope ");
        hint.push_str(scope_hint);
        hint.push_str(". Response body: ");
        hint.push_str(&body);
        return Err(SecretsError::Backend(hint));
    }

    Ok(response)
}

fn blocking_get_latest(
    client: &Client,
    auth: &AzureAuth,
    config: &AzureProviderConfig,
    name: &str,
) -> SecretsResult<Option<StoredSecret>> {
    let url = format!(
        "{}/{}?api-version={}",
        config.secrets_endpoint(),
        name,
        SECRETS_API_VERSION
    );
    let response = blocking_request(client, auth, config, Method::GET, url, None)?;
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
