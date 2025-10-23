use crate::wire;
use crate::{
    decode_list, decode_rotate, decode_secret, PutSecretRequest, Result, RotateSummary, SdkError,
    Secret,
};
use reqwest::Url;
use secrets_core::backend::SecretVersion;
use secrets_core::types::Scope;
use serde_json;
use std::time::Duration;

/// HTTP client for the Secrets Broker REST API.
#[derive(Clone)]
pub struct HttpClient {
    base_url: Url,
    client: reqwest::Client,
    token: Option<String>,
    timeout: Duration,
}

impl HttpClient {
    /// Build a new client using the provided base URL.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        let url = Url::parse(base_url.as_ref())
            .map_err(|err| SdkError::InvalidResponse(err.to_string()))?;
        let client = reqwest::Client::builder()
            .user_agent("greentic-secrets-sdk/0.1")
            .build()?;
        Ok(Self {
            base_url: url,
            client,
            token: None,
            timeout: Duration::from_secs(10),
        })
    }

    /// Attach a bearer token that will be sent with each request.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Override the request timeout (default 10 seconds).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Store a secret using the broker APIs.
    pub async fn put_secret(
        &self,
        scope: &Scope,
        category: &str,
        name: &str,
        request: &PutSecretRequest,
    ) -> Result<Secret> {
        let path = resource_path(scope, category, Some(name));
        let url = self
            .base_url
            .join(&path)
            .map_err(|err| SdkError::InvalidResponse(err.to_string()))?;
        let body = request.to_wire()?;
        let builder = self.client.put(url).timeout(self.timeout).json(&body);
        let response = ensure_success(self.apply_auth(builder).send().await?).await?;
        let payload = response.json::<wire::SecretResponse>().await?;
        decode_secret(payload)
    }

    /// Retrieve a secret, optionally specifying a version.
    pub async fn get_secret(
        &self,
        scope: &Scope,
        category: &str,
        name: &str,
        version: Option<u64>,
    ) -> Result<Option<Secret>> {
        let target_name = match version {
            Some(v) => format!("{name}@{v}"),
            None => name.to_string(),
        };
        let path = resource_path(scope, category, Some(&target_name));
        let url = self
            .base_url
            .join(&path)
            .map_err(|err| SdkError::InvalidResponse(err.to_string()))?;
        let builder = self.client.get(url).timeout(self.timeout);
        let response = self.apply_auth(builder).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = response.error_for_status()?;
        let payload = response.json::<wire::SecretResponse>().await?;
        decode_secret(payload).map(Some)
    }

    /// Delete a secret, returning the tombstone version.
    pub async fn delete_secret(
        &self,
        scope: &Scope,
        category: &str,
        name: &str,
    ) -> Result<SecretVersion> {
        let path = resource_path(scope, category, Some(name));
        let url = self
            .base_url
            .join(&path)
            .map_err(|err| SdkError::InvalidResponse(err.to_string()))?;
        let builder = self.client.delete(url).timeout(self.timeout);
        let response = ensure_success(self.apply_auth(builder).send().await?).await?;
        let payload = response.json::<wire::DeleteResponse>().await?;
        Ok(SecretVersion {
            version: payload.version,
            deleted: payload.deleted,
        })
    }

    /// List secrets for the provided scope.
    pub async fn list_secrets(
        &self,
        scope: &Scope,
        category_prefix: Option<&str>,
        name_prefix: Option<&str>,
    ) -> Result<Vec<crate::ListEntry>> {
        let path = list_path(scope);
        let mut url = self
            .base_url
            .join(&path)
            .map_err(|err| SdkError::InvalidResponse(err.to_string()))?;
        if let Some(prefix) = build_prefix(category_prefix, name_prefix) {
            url.query_pairs_mut().append_pair("prefix", &prefix);
        }
        let builder = self.client.get(url).timeout(self.timeout);
        let response = ensure_success(self.apply_auth(builder).send().await?).await?;
        let payload = response.json::<wire::ListSecretsResponse>().await?;
        decode_list(payload.items)
    }

    /// Return version metadata for a secret.
    pub async fn versions(
        &self,
        scope: &Scope,
        category: &str,
        name: &str,
    ) -> Result<Vec<SecretVersion>> {
        let path = format!("{}/_versions", resource_path(scope, category, Some(name)));
        let url = self
            .base_url
            .join(&path)
            .map_err(|err| SdkError::InvalidResponse(err.to_string()))?;
        let builder = self.client.get(url).timeout(self.timeout);
        let response = ensure_success(self.apply_auth(builder).send().await?).await?;
        let payload = response.json::<wire::VersionsResponse>().await?;
        Ok(payload.versions)
    }

    /// Trigger a category-wide rotation job.
    pub async fn rotate_category(
        &self,
        scope: &Scope,
        category: &str,
        job_id: Option<&str>,
    ) -> Result<RotateSummary> {
        let path = rotate_path(scope, category);
        let url = self
            .base_url
            .join(&path)
            .map_err(|err| SdkError::InvalidResponse(err.to_string()))?;
        let body = job_id.map(|value| serde_json::json!({ "job_id": value }));
        let builder = if let Some(body) = body {
            self.client.post(url).timeout(self.timeout).json(&body)
        } else {
            self.client.post(url).timeout(self.timeout)
        };
        let response = ensure_success(self.apply_auth(builder).send().await?).await?;
        let payload = response.json::<wire::RotateResponse>().await?;
        Ok(decode_rotate(payload))
    }

    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.token {
            builder.bearer_auth(token)
        } else {
            builder
        }
    }
}

fn resource_path(scope: &Scope, category: &str, name: Option<&str>) -> String {
    let mut path = format!("/v1/{}/{}", scope.env(), scope.tenant());
    if let Some(team) = scope.team() {
        path.push('/');
        path.push_str(team);
    }
    path.push('/');
    path.push_str(category);
    if let Some(name) = name {
        path.push('/');
        path.push_str(name);
    }
    path
}

fn list_path(scope: &Scope) -> String {
    let mut path = format!("/v1/{}/{}", scope.env(), scope.tenant());
    if let Some(team) = scope.team() {
        path.push('/');
        path.push_str(team);
    }
    path.push_str("/_list");
    path
}

fn rotate_path(scope: &Scope, category: &str) -> String {
    let mut path = format!("/v1/{}/{}", scope.env(), scope.tenant());
    if let Some(team) = scope.team() {
        path.push('/');
        path.push_str(team);
    }
    path.push_str("/_rotate/");
    path.push_str(category);
    path
}

fn build_prefix(category: Option<&str>, name: Option<&str>) -> Option<String> {
    match (category, name) {
        (None, None) => None,
        (Some(category), None) => Some(category.to_string()),
        (Some(category), Some(name)) => Some(format!("{category}/{name}")),
        (None, Some(name)) => Some(format!("/{name}")),
    }
}

async fn ensure_success(response: reqwest::Response) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }

    let status = response.status();
    let bytes = response.bytes().await?;
    if let Ok(err) = serde_json::from_slice::<wire::ErrorResponse>(&bytes) {
        return Err(SdkError::Broker(err.message));
    }

    let body = String::from_utf8_lossy(&bytes).to_string();
    Err(SdkError::InvalidResponse(format!("http {status}: {body}")))
}
