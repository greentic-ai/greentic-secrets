use secrets_core::backend::SecretVersion;
use secrets_core::types::{ContentType, Visibility};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct PutSecretRequest {
    pub visibility: Visibility,
    pub content_type: ContentType,
    pub encoding: ValueEncoding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct PutCommand {
    pub category: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(flatten)]
    pub body: PutSecretRequest,
}

#[derive(Debug, Serialize)]
pub struct GetCommand {
    pub category: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListCommand {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteCommand {
    pub category: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RotateCommand {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SecretResponse {
    pub uri: String,
    pub version: u64,
    pub visibility: Visibility,
    pub content_type: ContentType,
    pub encoding: ValueEncoding,
    pub value: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListSecretsResponse {
    pub items: Vec<ListItem>,
}

#[derive(Debug, Deserialize)]
pub struct ListItem {
    pub uri: String,
    pub visibility: Visibility,
    pub content_type: ContentType,
    pub latest_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VersionsResponse {
    pub versions: Vec<SecretVersion>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteResponse {
    pub version: u64,
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
pub struct RotateResponse {
    pub job_id: String,
    pub category: String,
    pub rotated: usize,
    pub skipped: usize,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ValueEncoding {
    Utf8,
    Base64,
}
