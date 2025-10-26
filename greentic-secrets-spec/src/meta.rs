use crate::error::Result;
use crate::key::{Scope, SecretUri};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// Visibility boundary for a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum Visibility {
    User,
    Team,
    Tenant,
}

impl Visibility {
    const fn level(self) -> u8 {
        match self {
            Self::User => 0,
            Self::Team => 1,
            Self::Tenant => 2,
        }
    }

    pub fn allows(self, required: Visibility) -> bool {
        self.level() >= required.level()
    }
}

/// Supported content encoding for stored secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum ContentType {
    Opaque,
    Json,
    Text,
    Binary,
}

/// Supported encryption algorithms for envelope operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

impl EncryptionAlgorithm {
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes256gcm",
            Self::XChaCha20Poly1305 => "xchacha",
        }
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EncryptionAlgorithm {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        let value = s.trim().to_ascii_lowercase();
        match value.as_str() {
            "" => Ok(Self::Aes256Gcm),
            "aes256gcm" | "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "xchacha" | "xchacha20" | "xchacha20poly1305" => Ok(Self::XChaCha20Poly1305),
            other => Err(crate::error::Error::UnsupportedAlgorithm(other.into())),
        }
    }
}

/// High-level metadata about a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "serde", serde(default))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretMeta {
    pub uri: SecretUri,
    pub visibility: Visibility,
    pub content_type: ContentType,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub description: Option<String>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "BTreeMap::is_empty"))]
    pub tags: BTreeMap<String, String>,
}

impl SecretMeta {
    pub fn new(uri: SecretUri, visibility: Visibility, content_type: ContentType) -> Self {
        Self {
            uri,
            visibility,
            content_type,
            description: None,
            tags: BTreeMap::new(),
        }
    }

    pub fn scope(&self) -> &Scope {
        self.uri.scope()
    }

    pub fn tags(&self) -> &BTreeMap<String, String> {
        &self.tags
    }

    pub fn tags_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.tags
    }

    pub fn set_tag(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.tags.insert(key.into(), value.into());
    }

    pub fn remove_tag(&mut self, key: &str) -> Option<String> {
        self.tags.remove(key)
    }
}

/// Summary information for secret listings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SecretListItem {
    pub uri: SecretUri,
    pub visibility: Visibility,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub latest_version: Option<String>,
    pub content_type: ContentType,
}

impl SecretListItem {
    pub fn from_meta(meta: &SecretMeta, latest_version: Option<String>) -> Self {
        Self {
            uri: meta.uri.clone(),
            visibility: meta.visibility,
            latest_version,
            content_type: meta.content_type,
        }
    }
}
