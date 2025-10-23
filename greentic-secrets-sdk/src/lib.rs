//! Rust SDK for interacting with the Secrets Broker over HTTP and NATS.

pub mod helpers;
pub mod http_client;
pub mod nats_client;

mod wire;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
pub use secrets_core::types::{ContentType, Scope, Visibility};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use thiserror::Error;

pub use helpers::{get_bin, get_json, get_text, put_bin, put_json, put_text};
pub use http_client::HttpClient;
pub use nats_client::NatsClient;

/// Result type used throughout the SDK.
pub type Result<T> = std::result::Result<T, SdkError>;

/// Minimal error surface for the SDK.
#[derive(Debug, Error)]
pub enum SdkError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("nats error: {0}")]
    Nats(#[from] async_nats::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("broker error: {0}")]
    Broker(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

impl From<serde_json::Error> for SdkError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

/// Secret metadata returned by the SDK.
#[derive(Debug, Clone)]
pub struct SecretMetadata {
    pub uri: String,
    pub visibility: Visibility,
    pub content_type: ContentType,
    pub description: Option<String>,
    pub tags: HashMap<String, String>,
}

/// Decrypted secret payload and metadata.
#[derive(Debug, Clone)]
pub struct Secret {
    pub version: u64,
    pub metadata: SecretMetadata,
    pub value: Vec<u8>,
}

impl Secret {
    /// Interpret the secret payload as UTF-8 text.
    pub fn as_text(&self) -> Result<String> {
        String::from_utf8(self.value.clone())
            .map_err(|err| SdkError::InvalidResponse(err.to_string()))
    }

    /// Deserialize the payload as JSON.
    pub fn as_json<T: DeserializeOwned>(&self) -> Result<T> {
        let bytes = &self.value;
        serde_json::from_slice(bytes).map_err(SdkError::from)
    }
}

/// Summary returned from list operations.
#[derive(Debug, Clone)]
pub struct ListEntry {
    pub metadata: SecretMetadata,
    pub latest_version: Option<u64>,
}

/// Rotation job summary.
#[derive(Debug, Clone)]
pub struct RotateSummary {
    pub job_id: String,
    pub category: String,
    pub rotated: usize,
    pub skipped: usize,
}

/// Encoding to use when sending payloads to the broker.
#[derive(Debug, Clone, Copy)]
pub enum PayloadEncoding {
    Utf8,
    Base64,
}

impl From<PayloadEncoding> for wire::ValueEncoding {
    fn from(value: PayloadEncoding) -> Self {
        match value {
            PayloadEncoding::Utf8 => wire::ValueEncoding::Utf8,
            PayloadEncoding::Base64 => wire::ValueEncoding::Base64,
        }
    }
}

/// Request body used by client operations that create or update secrets.
#[derive(Debug, Clone)]
pub struct PutSecretRequest {
    pub visibility: Visibility,
    pub content_type: ContentType,
    pub description: Option<String>,
    pub value: Vec<u8>,
    pub encoding: PayloadEncoding,
}

impl PutSecretRequest {
    /// Construct a request from raw bytes using base64 encoding.
    pub fn from_bytes(visibility: Visibility, content_type: ContentType, value: Vec<u8>) -> Self {
        Self {
            visibility,
            content_type,
            description: None,
            value,
            encoding: PayloadEncoding::Base64,
        }
    }

    /// Construct a request from UTF-8 text.
    pub fn from_text(
        visibility: Visibility,
        content_type: ContentType,
        value: impl Into<String>,
    ) -> Self {
        Self {
            visibility,
            content_type,
            description: None,
            value: value.into().into_bytes(),
            encoding: PayloadEncoding::Utf8,
        }
    }

    /// Update the optional description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub(crate) fn to_wire(&self) -> Result<wire::PutSecretRequest> {
        let value = match self.encoding {
            PayloadEncoding::Utf8 => String::from_utf8(self.value.clone())
                .map_err(|err| SdkError::Serialization(err.to_string()))?,
            PayloadEncoding::Base64 => STANDARD_NO_PAD.encode(&self.value),
        };
        Ok(wire::PutSecretRequest {
            visibility: self.visibility,
            content_type: self.content_type,
            encoding: self.encoding.into(),
            description: self.description.clone(),
            value,
        })
    }
}

pub(crate) fn decode_secret(response: wire::SecretResponse) -> Result<Secret> {
    let value = match response.encoding {
        wire::ValueEncoding::Utf8 => response.value.into_bytes(),
        wire::ValueEncoding::Base64 => STANDARD_NO_PAD
            .decode(response.value.as_bytes())
            .map_err(|err| SdkError::InvalidResponse(err.to_string()))?,
    };

    let metadata = SecretMetadata {
        uri: response.uri,
        visibility: response.visibility,
        content_type: response.content_type,
        description: response.description,
        tags: HashMap::new(),
    };

    Ok(Secret {
        version: response.version,
        metadata,
        value,
    })
}

pub(crate) fn decode_list(items: Vec<wire::ListItem>) -> Result<Vec<ListEntry>> {
    items
        .into_iter()
        .map(|item| {
            let latest_version = match item.latest_version {
                Some(ref value) if value.is_empty() => None,
                Some(value) => Some(
                    value
                        .parse::<u64>()
                        .map_err(|err| SdkError::InvalidResponse(err.to_string()))?,
                ),
                None => None,
            };

            let metadata = SecretMetadata {
                uri: item.uri,
                visibility: item.visibility,
                content_type: item.content_type,
                description: None,
                tags: HashMap::new(),
            };

            Ok(ListEntry {
                metadata,
                latest_version,
            })
        })
        .collect()
}

pub(crate) fn decode_rotate(response: wire::RotateResponse) -> RotateSummary {
    RotateSummary {
        job_id: response.job_id,
        category: response.category,
        rotated: response.rotated,
        skipped: response.skipped,
    }
}
