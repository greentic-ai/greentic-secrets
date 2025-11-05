use anyhow::{Context, Result};
use serde::Deserialize;
use std::time::Duration;

const TOKEN_ENDPOINT_TEMPLATE: &str =
    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token";

#[derive(Clone, Debug)]
pub struct KvAuthConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub scope: String,
}

impl KvAuthConfig {
    pub fn from_env() -> Result<Self> {
        let tenant_id =
            std::env::var("AZURE_TENANT_ID").context("missing AZURE_TENANT_ID for Azure auth")?;
        let client_id =
            std::env::var("AZURE_CLIENT_ID").context("missing AZURE_CLIENT_ID for Azure auth")?;
        let client_secret = std::env::var("AZURE_CLIENT_SECRET")
            .context("missing AZURE_CLIENT_SECRET for Azure auth")?;
        let scope = std::env::var("AZURE_KV_SCOPE")
            .unwrap_or_else(|_| "https://vault.azure.net/.default".to_string());

        Ok(Self {
            tenant_id,
            client_id,
            client_secret,
            scope,
        })
    }
}

#[derive(Debug)]
pub struct AccessToken {
    pub token: String,
    pub expires_in: Duration,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AuthError {
    #[error("token endpoint rejected the request: {status} {body}")]
    Unauthorized {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("failed to request token: {0}")]
    Request(String),
    #[error("failed to parse token response: {0}")]
    Parse(String),
}

pub fn request_access_token(
    client: &reqwest::blocking::Client,
    cfg: &KvAuthConfig,
) -> Result<AccessToken, AuthError> {
    let url = TOKEN_ENDPOINT_TEMPLATE.replace("{tenant}", &cfg.tenant_id);
    let params = [
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("scope", cfg.scope.as_str()),
        ("grant_type", "client_credentials"),
    ];

    let response = client
        .post(url)
        .form(&params)
        .send()
        .map_err(|err| AuthError::Request(err.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(AuthError::Unauthorized { status, body });
    }

    let payload: TokenResponse = response
        .json()
        .map_err(|err| AuthError::Parse(err.to_string()))?;

    let expires_in = payload
        .expires_in
        .unwrap_or(3600)
        .saturating_sub(60)
        .max(60);

    Ok(AccessToken {
        token: payload.access_token,
        expires_in: Duration::from_secs(expires_in as u64),
    })
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u32>,
}
