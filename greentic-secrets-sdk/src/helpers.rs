use crate::{HttpClient, PutSecretRequest, Result, Secret};
use secrets_core::types::{ContentType, Scope, Visibility};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Store a JSON value using the HTTP client.
pub async fn put_json<T: Serialize>(
    client: &HttpClient,
    scope: &Scope,
    category: &str,
    name: &str,
    value: &T,
    visibility: Visibility,
    description: Option<&str>,
) -> Result<Secret> {
    let json = serde_json::to_string(value)?;
    let mut request = PutSecretRequest::from_text(visibility, ContentType::Json, json);
    if let Some(desc) = description {
        request = request.with_description(desc);
    }
    client.put_secret(scope, category, name, &request).await
}

/// Retrieve JSON content, returning `None` when the secret is missing.
pub async fn get_json<T: DeserializeOwned>(
    client: &HttpClient,
    scope: &Scope,
    category: &str,
    name: &str,
    version: Option<u64>,
) -> Result<Option<T>> {
    match client.get_secret(scope, category, name, version).await? {
        Some(secret) => secret.as_json().map(Some),
        None => Ok(None),
    }
}

/// Store textual content using UTF-8 encoding.
pub async fn put_text(
    client: &HttpClient,
    scope: &Scope,
    category: &str,
    name: &str,
    value: impl Into<String>,
    visibility: Visibility,
    description: Option<&str>,
) -> Result<Secret> {
    let mut request = PutSecretRequest::from_text(visibility, ContentType::Text, value);
    if let Some(desc) = description {
        request = request.with_description(desc);
    }
    client.put_secret(scope, category, name, &request).await
}

/// Retrieve text content, returning `None` when absent.
pub async fn get_text(
    client: &HttpClient,
    scope: &Scope,
    category: &str,
    name: &str,
    version: Option<u64>,
) -> Result<Option<String>> {
    match client.get_secret(scope, category, name, version).await? {
        Some(secret) => secret.as_text().map(Some),
        None => Ok(None),
    }
}

/// Store binary data using base64 encoding.
pub async fn put_bin(
    client: &HttpClient,
    scope: &Scope,
    category: &str,
    name: &str,
    value: Vec<u8>,
    visibility: Visibility,
    description: Option<&str>,
) -> Result<Secret> {
    let mut request = PutSecretRequest::from_bytes(visibility, ContentType::Binary, value);
    if let Some(desc) = description {
        request = request.with_description(desc);
    }
    client.put_secret(scope, category, name, &request).await
}

/// Retrieve binary data, returning `None` when the secret is missing.
pub async fn get_bin(
    client: &HttpClient,
    scope: &Scope,
    category: &str,
    name: &str,
    version: Option<u64>,
) -> Result<Option<Vec<u8>>> {
    match client.get_secret(scope, category, name, version).await? {
        Some(secret) => Ok(Some(secret.value)),
        None => Ok(None),
    }
}
