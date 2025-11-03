use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use secrets_core::backend::SecretVersion;
use secrets_core::types::{ContentType, SecretListItem, SecretMeta, Visibility};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppErrorKind};

type PutSecretPayload = (
    Vec<u8>,
    ValueEncoding,
    ContentType,
    Visibility,
    Option<String>,
);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ValueEncoding {
    Utf8,
    #[default]
    Base64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutSecretRequest {
    pub visibility: Visibility,
    pub content_type: ContentType,
    #[serde(default)]
    pub encoding: ValueEncoding,
    #[serde(default)]
    pub description: Option<String>,
    pub value: String,
}

impl PutSecretRequest {
    pub fn into_bytes(self) -> Result<PutSecretPayload, AppError> {
        let encoding = self.encoding;
        let content_type = self.content_type;
        let visibility = self.visibility;
        let description = self.description;
        let value = match encoding {
            ValueEncoding::Utf8 => self.value.into_bytes(),
            ValueEncoding::Base64 => STANDARD_NO_PAD
                .decode(self.value.as_bytes())
                .map_err(|err| AppError::new(AppErrorKind::BadRequest(err.to_string())))?,
        };
        Ok((value, encoding, content_type, visibility, description))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretResponse {
    pub uri: String,
    pub version: u64,
    pub visibility: Visibility,
    pub content_type: ContentType,
    pub encoding: ValueEncoding,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl SecretResponse {
    pub fn from_meta(meta: &SecretMeta, version: u64, value: &[u8]) -> Self {
        let (value, encoding) = encode_value(meta.content_type, value);
        Self {
            uri: meta.uri.to_string(),
            version,
            visibility: meta.visibility,
            content_type: meta.content_type,
            encoding,
            value,
            description: meta.description.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSecretsResponse {
    pub items: Vec<ListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListItem {
    pub uri: String,
    pub visibility: Visibility,
    pub content_type: ContentType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
}

impl From<SecretListItem> for ListItem {
    fn from(value: SecretListItem) -> Self {
        Self {
            uri: value.uri.to_string(),
            visibility: value.visibility,
            content_type: value.content_type,
            latest_version: value.latest_version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionsResponse {
    pub versions: Vec<VersionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: u64,
    pub deleted: bool,
}

impl From<SecretVersion> for VersionInfo {
    fn from(value: SecretVersion) -> Self {
        Self {
            version: value.version,
            deleted: value.deleted,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub version: u64,
    pub deleted: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct RotateRequest {
    #[serde(default)]
    pub job_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotateResponse {
    pub job_id: String,
    pub category: String,
    pub rotated: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PutCommand {
    pub category: String,
    pub name: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(flatten)]
    pub body: PutSecretRequest,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GetCommand {
    pub category: String,
    pub name: String,
    pub version: Option<u64>,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListCommand {
    pub prefix: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeleteCommand {
    pub category: String,
    pub name: String,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RotateCommand {
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub correlation_id: String,
}

pub fn encode_value(content_type: ContentType, bytes: &[u8]) -> (String, ValueEncoding) {
    match content_type {
        ContentType::Text | ContentType::Json => match String::from_utf8(bytes.to_vec()) {
            Ok(text) => (text, ValueEncoding::Utf8),
            Err(_) => (STANDARD_NO_PAD.encode(bytes), ValueEncoding::Base64),
        },
        ContentType::Opaque | ContentType::Binary => {
            (STANDARD_NO_PAD.encode(bytes), ValueEncoding::Base64)
        }
    }
}
